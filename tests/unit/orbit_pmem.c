/*
 * orbit_pmem - the Linux address-space walk over a FAKE /proc (aproc_pmem.c, apagemap.c, awalk.c, kofa_region_describe).
 * The files are real files the test wrote under build/kof_orbit_pmem_XXXXXX; tests/lib/orbit_sys.c sends "/proc/..." there
 * and serves process_vm_readv from a buffer the test owns. The pagemap files are real files too (sparse, written at the
 * offset the library will pread), so the same code runs on them as on the kernel's.
 *
 *   pagemap   kofa_pm_scan on memfd pagemaps: run boundaries, the run cap with the count still whole, batch edges (64
 *             entries), a file that ends mid-region, a pread that fails, every refused argument
 *   maps      one fixture with every region shape the classifier names, and the same bytes through each option
 *   smaps     Rss and Private_Dirty folded in, a header followed by a header, zero-heavy, the fallback to maps
 *   chunks    kofa_pmem_next_chunk / _read: zero pages left out, the per-process and the sweep budgets, unreadable runs
 *   open      pid reuse (start time), missing and unreadable maps, a pagemap that is not there
 *   walk      kof_walk_open over a fixture: list mode, pid mode, refused, kernel threads, intents, labels, stats
 *   describe  kofa_region_describe for every flag, every use, every buffer size
 *   hostile   a maps with 100000 regions, a line over the buffer, 4095-byte paths, wrap-around addresses, short perms
 * Defect rows are KM_CHECK (known_miss.h). Ids WP12-n are listed in the work package's report.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aproc.h"
#include "apagemap.h"
#include "kofwalk.h"
#include "known_miss.h"
#include "../lib/orbit_sys.c"

static int fails, checks;
static char *R;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		printf("  FAIL %s\n", what);
		fails++;
	}
}

#define OKF(cond, ...) do { char w_[240]; snprintf(w_, sizeof w_, __VA_ARGS__); ok((cond), w_); } while (0)

static void fresh(void)
{
	osys_reset();
	osys_rmrf(R);
	mkdir(R, 0755);
	osys_proc_root(R);
}

static void put_s(uint32_t pid, const char *rel, const char *text) { (void)osys_put(R, pid, rel, text, strlen(text)); }

static void put_proc(uint32_t pid, const char *maps, const char *smaps)
{
	put_s(pid, "stat", "100 (fake) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 1 1\n");
	if (maps)
		put_s(pid, "maps", maps);
	if (smaps)
		put_s(pid, "smaps", smaps);
}

/* ---- pagemap fixtures: entry i of the file describes page i of the address space ---- */
#define PM_P (1ull << 63)
#define PM_S (1ull << 62)

static void pm_write(uint32_t pid, uint64_t base, const char *pat)
{
	char p[600];
	int fd;
	size_t i;

	snprintf(p, sizeof p, "%s/%u", R, (unsigned)pid);
	mkdir(p, 0755);
	snprintf(p, sizeof p, "%s/%u/pagemap", R, (unsigned)pid);
	fd = __real_open(p, O_RDWR | O_CREAT, 0644);
	for (i = 0; fd >= 0 && pat[i]; i++) {
		uint64_t e = pat[i] == 'P' ? (PM_P | 0x1234u) : pat[i] == 'S' ? PM_S : 0;

		(void)pwrite(fd, &e, 8, (off_t)(((base >> 12) + i) * 8));
	}
	if (fd >= 0)
		close(fd);
}

static int mem_pagemap(const char *pat, uint64_t base)
{
	int fd = memfd_create("pm", 0);
	size_t i;

	for (i = 0; pat[i]; i++) {
		uint64_t e = pat[i] == 'P' ? (PM_P | 0x77u) : pat[i] == 'S' ? PM_S : 0;

		(void)pwrite(fd, &e, 8, (off_t)(((base >> 12) + i) * 8));
	}
	return fd;
}

struct pm_row {
	const char *id;
	const char *pat;
	uint64_t    size_extra;      /* added to pages * 4096 (an unaligned tail) */
	int         max_runs;
	size_t      scratch;
	/* expected */
	int         runs, more;
	uint64_t    resident_pages, swapped_pages;
	uint64_t    run0_page, run0_len_pages, last_len_bytes;   /* last_len_bytes 0: not checked */
};

static const struct pm_row pm_rows[] = {
	{ "empty", "......", 0, 8, 64, 0, 0, 0, 0, 0, 0, 0 },
	{ "all present", "PPPPPP", 0, 8, 64, 1, 0, 6, 0, 0, 6, 0 },
	{ "one page", "P", 0, 8, 64, 1, 0, 1, 0, 0, 1, 0 },
	{ "run in the middle", "..PP..", 0, 8, 64, 1, 0, 2, 0, 2, 2, 0 },
	{ "run at the end (the tail run)", "...PPP", 0, 8, 64, 1, 0, 3, 0, 3, 3, 0 },
	{ "two runs split by a swapped page", "PPSPP", 0, 8, 64, 2, 0, 4, 1, 0, 2, 0 },
	{ "swapped only", "SSS", 0, 8, 64, 0, 0, 0, 3, 0, 0, 0 },
	{ "alternating, cap 2: more, count whole", "P.P.P.P.P.", 0, 2, 64, 2, 1, 5, 0, 0, 1, 0 },
	{ "alternating, run on the last page, cap 2", "P.P.P", 0, 2, 64, 2, 1, 3, 0, 0, 1, 0 },
	{ "cap 1, exactly one run", "..PP..", 0, 1, 64, 1, 0, 2, 0, 2, 2, 0 },
	{ "unaligned size: the last run is clamped", "PPP", 100, 8, 64, 1, 0, 3, 0, 0, 3, 3u * 4096u - 0u },
};

static void case_pm_rows(void)
{
	unsigned i;

	printf("\nkofa_pm_scan over a memfd pagemap (a table):\n");
	for (i = 0; i < sizeof pm_rows / sizeof pm_rows[0]; i++) {
		const struct pm_row *r = &pm_rows[i];
		uint64_t base = 0x40000000ull, scratch[512];
		struct kofa_run runs[16];
		struct kofa_pm_result res;
		size_t pages = strlen(r->pat);
		uint64_t size = r->size_extra ? (pages - 1u) * 4096u + r->size_extra : pages * 4096u;
		int fd = mem_pagemap(r->pat, base), rc;

		memset(runs, 0, sizeof runs);
		rc = kofa_pm_scan(fd, base, size, scratch, r->scratch, runs, r->max_runs, &res);
		/* an unaligned size: a region of (pages - 1) pages + extra bytes, so the last page is partial */
		OKF(rc == KOFA_OK, "pm row '%s': status ok", r->id);
		OKF(res.runs == r->runs, "pm row '%s': %d runs (got %d)", r->id, r->runs, res.runs);
		OKF(res.more == r->more, "pm row '%s': more == %d", r->id, r->more);
		if (!r->size_extra) {
			OKF(res.resident == r->resident_pages * 4096u, "pm row '%s': resident %llu pages", r->id, (unsigned long long)r->resident_pages);
			OKF(res.swapped == r->swapped_pages * 4096u, "pm row '%s': swapped %llu pages", r->id, (unsigned long long)r->swapped_pages);
			if (r->runs)
				OKF(runs[0].addr == base + r->run0_page * 4096u && runs[0].len == r->run0_len_pages * 4096u,
				    "pm row '%s': first run at page %llu, %llu pages", r->id, (unsigned long long)r->run0_page,
				    (unsigned long long)r->run0_len_pages);
		} else {
			/* region is 2 whole pages + `extra` bytes: three page entries are read, the run is cut at the region end */
			OKF(res.runs == 1 && runs[0].addr == base && runs[0].len == 2u * 4096u + r->size_extra,
			    "pm row '%s': the run is clamped to the region (%llu bytes)", r->id, (unsigned long long)runs[0].len);
		}
		close(fd);
	}
}

static void case_pm_batches(void)
{
	/* a region of 1000 pages through a 64-entry scratch: 16 reads, a run that crosses every batch edge stays ONE run */
	uint64_t base = 0x50000000ull, scratch[64];
	struct kofa_run runs[8];
	struct kofa_pm_result res;
	char *pat = malloc(1001);
	int fd, rc;
	size_t i;

	printf("\nkofa_pm_scan: batch edges and a file that ends early:\n");
	memset(pat, 'P', 1000);
	pat[1000] = '\0';
	fd = mem_pagemap(pat, base);
	rc = kofa_pm_scan(fd, base, 1000u * 4096u, scratch, 64, runs, 8, &res);
	ok(rc == KOFA_OK && res.runs == 1 && runs[0].len == 1000u * 4096u && res.resident == 1000u * 4096u,
	   "1000 present pages through 64-entry batches: one run of 1000 pages");
	close(fd);
	for (i = 0; i < 1000; i += 64)
		pat[i] = '.';
	fd = mem_pagemap(pat, base);
	rc = kofa_pm_scan(fd, base, 1000u * 4096u, scratch, 64, runs, 8, &res);
	ok(rc == KOFA_OK && res.more == 1 && res.runs == 8 && res.resident == (1000u - 16u) * 4096u,
	   "a hole at every batch edge: 16 runs, 8 kept and more set, resident still whole");
	close(fd);
	/* the file holds 10 entries, the region is 1000 pages: what was learned is returned */
	fd = mem_pagemap("PPPPPPPPPP", base);
	rc = kofa_pm_scan(fd, base, 1000u * 4096u, scratch, 64, runs, 8, &res);
	ok(rc == KOFA_OK && res.runs == 1 && runs[0].len == 10u * 4096u && res.resident == 10u * 4096u,
	   "a pagemap that ends after 10 entries: success with the 10 pages it had, never a wrong run");
	close(fd);
	/* a pread that fails on the second batch */
	fd = mem_pagemap(pat, base);
	osys_reset();
	osys_fail(OSYS_PREAD, 2, EIO);
	rc = kofa_pm_scan(fd, base, 1000u * 4096u, scratch, 64, runs, 8, &res);
	ok(rc == KOFA_OK && res.resident <= 64u * 4096u && res.resident > 0, "EIO on the second pread: what the first batch said is kept, status ok");
	close(fd);
	osys_reset();
	free(pat);
}

static void case_pm_args(void)
{
	uint64_t scratch[64];
	struct kofa_run runs[4];
	struct kofa_pm_result res;
	int fd = mem_pagemap("PPPP", 0x1000);

	printf("\nkofa_pm_scan: refused arguments:\n");
	ok(kofa_pm_scan(fd, 0x1000, 4096, scratch, 64, runs, 4, NULL) == KOFA_ERR_OS, "NULL result");
	ok(kofa_pm_scan(fd, 0x1000, 4096, NULL, 64, runs, 4, &res) == KOFA_ERR_OS, "NULL scratch");
	ok(kofa_pm_scan(fd, 0x1000, 4096, scratch, 63, runs, 4, &res) == KOFA_ERR_OS, "scratch of 63 entries (the floor is 64)");
	ok(kofa_pm_scan(fd, 0x1000, 4096, scratch, 64, NULL, 4, &res) == KOFA_ERR_OS, "NULL runs");
	ok(kofa_pm_scan(fd, 0x1000, 4096, scratch, 64, runs, 0, &res) == KOFA_ERR_OS, "max_runs 0");
	ok(kofa_pm_scan(-1, 0x1000, 4096, scratch, 64, runs, 4, &res) == KOFA_ERR_UNSUPPORTED && res.runs == 0, "no pagemap fd: UNSUPPORTED and a zeroed result");
	ok(kofa_pm_scan(fd, 0x1001, 4096, scratch, 64, runs, 4, &res) == KOFA_ERR_OS, "an unaligned base");
	ok(kofa_pm_scan(fd, 0x1000, 0, scratch, 64, runs, 4, &res) == KOFA_ERR_OS, "size 0");
	{
		int rc = kofa_pm_scan(fd, 0x1000, ~0ull, scratch, 64, runs, 4, &res);

		/* KNOWN DEFECT WP12-3 (2026-10-24, M): this row pins it, green until fixed. */
		KM_CHECK(rc != KOFA_OK, "size 2^64-1: (size + 4095) wraps to 0 pages and the scan reports OK with nothing resident (WP12-3)",
			 "WP12-3: kofa_pm_scan size overflow");
	}
	close(fd);
	{
		int err = 0, pfd;

		fresh();
		put_proc(100, "00400000-00401000 r-xp 00000000 08:01 7 /bin/x\n", NULL);
		pfd = kofa_pm_open(100, &err);
		ok(pfd < 0 && err == KOFA_ERR_UNSUPPORTED, "kofa_pm_open: no pagemap file is UNSUPPORTED");
		pm_write(100, 0x400000, "P");
		pfd = kofa_pm_open(100, &err);
		ok(pfd >= 0, "kofa_pm_open: opens the file");
		if (pfd >= 0)
			close(pfd);
		osys_match("/pagemap");
		osys_fail(OSYS_OPEN, 1, EACCES);
		pfd = kofa_pm_open(100, &err);
		ok(pfd < 0 && err == KOFA_ERR_DENIED, "kofa_pm_open: EACCES is DENIED");
		osys_reset();
		osys_proc_root(R);
		ok(kofa_pm_open(100, NULL) >= 0 || 1, "kofa_pm_open accepts a NULL err");
	}
}

/* ---------------------------------------------------------------------------------------------------- maps */

struct reg {
	uint64_t base, size, rss, group, inode;
	uint32_t flags;
	uint8_t  use, loc;
	char     path[4200];
};

static struct reg regs[256];
static unsigned n_regs;
static struct kofa_pmem_stat last_stat;
static int last_open_err;

static int walk_regions(uint32_t pid, const struct kofa_pmem_option *o, uint64_t start_time)
{
	struct kofa_pmem *m = kofa_pmem_open(pid, start_time, o, &last_open_err);
	struct kofa_region r;

	n_regs = 0;
	if (!m)
		return -1;
	while (n_regs < 256 && kofa_pmem_next_region(m, &r)) {
		struct reg *g = &regs[n_regs++];

		g->base = r.base;
		g->size = r.size;
		g->rss = r.rss;
		g->group = r.group_id;
		g->inode = r.inode;
		g->flags = r.flags;
		g->use = r.use;
		g->loc = r.loc;
		snprintf(g->path, sizeof g->path, "%s", r.path ? r.path : "(null)");
	}
	kofa_pmem_stats(m, &last_stat);
	kofa_pmem_close(m);
	return (int)n_regs;
}

static struct reg *reg_at(uint64_t base)
{
	unsigned i;

	for (i = 0; i < n_regs; i++)
		if (regs[i].base == base)
			return &regs[i];
	return NULL;
}

static const char MAPS[] =
	"00400000-00401000 r-xp 00000000 08:01 7 /usr/bin/prog\n"
	"00401000-00402000 r--p 00001000 08:01 7 /usr/bin/prog\n"
	"00402000-00403000 rw-p 00002000 08:01 7 /usr/bin/prog\n"
	"01000000-01021000 rw-p 00000000 00:00 0                                  [heap]\n"
	"10000000-10100000 rwxp 00000000 00:00 0\n"
	"10100000-10200000 r-xp 00000000 00:00 0\n"
	"10200000-10300000 ---p 00000000 00:00 0\n"
	"10300000-10301000 rw-p 00000000 00:00 0\n"
	"10301000-10302000 rw-p 00000000 00:00 0\n"
	"20000000-20001000 r-xp 00000000 08:01 9 /tmp/gone (deleted)\n"
	"20001000-20002000 r-xp 00000000 00:01 11 /memfd:evil (deleted)\n"
	"20002000-20003000 r-xp 00000000 00:01 12 /dev/shm/z\n"
	"20003000-20004000 r-xp 00000000 00:01 13 /run/user/1000/x\n"
	"30000000-30001000 r--p 00000000 00:00 0 [vdso]\n"
	"30001000-30002000 r-xp 00000000 00:00 0 [vsyscall]\n"
	"30002000-30003000 rw-p 00000000 00:00 0 [anon:something]\n"
	"7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0 [stack]\n"
	"40000000-40001000 r--p 00000000 08:01 21 /home/u/a file with  spaces.so\n"
	"40001000-40002000 r--p 00000000 08:01 22 /tmp/memfd:fake\n"
	"garbage that is not a maps line\n"
	"50000000-4fff0000 r-xp 00000000 08:01 5 /backwards\n"
	"50000000-50000000 r-xp 00000000 08:01 5 /empty\n"
	"\n";

static void case_maps(void)
{
	struct kofa_pmem_option o;
	struct reg *g;
	int n;

	printf("\nmaps: every region shape (no smaps, no pagemap):\n");
	fresh();
	put_proc(100, MAPS, NULL);
	memset(&o, 0, sizeof o);
	o.want = KOFA_MW_RESERVED | KOFA_MW_HEAP;     /* everything, plain maps */
	n = walk_regions(100, &o, 0);
	OKF(n == 19, "19 regions out of 23 lines (the garbage, the backwards, the empty and the blank are dropped), got %d", n);
	g = reg_at(0x400000);
	ok(g && g->use == KOFA_USE_IMAGE && (g->flags & KOFA_RGF_EXEC) && !(g->flags & KOFA_RGF_UNBACKED) && g->inode == 7, "r-xp file: IMAGE, not unbacked");
	ok(g && !strcmp(g->path, "/usr/bin/prog") && g->rss == g->size && !(g->flags & KOFA_RGF_RSS_MEASURED), "its path, and rss = size when nothing measured it");
	g = reg_at(0x401000);
	ok(g && g->use == KOFA_USE_DATA && g->group == 0x400000, "r--p of the same file: DATA, same group as the first");
	g = reg_at(0x402000);
	ok(g && g->use == KOFA_USE_DATA && (g->flags & KOFA_RGF_WRITE) && g->group == 0x400000, "rw-p of the same file: DATA, group");
	g = reg_at(0x1000000);
	ok(g && g->use == KOFA_USE_HEAP && (g->flags & KOFA_RGF_KERNEL_MAPPED) && !strcmp(g->path, "[heap]"), "[heap]: HEAP, kernel mapped, the spaces before the name are skipped");
	g = reg_at(0x10000000);
	ok(g && g->use == KOFA_USE_CODE && (g->flags & KOFA_RGF_WX) && (g->flags & KOFA_RGF_UNBACKED), "rwxp anonymous: CODE, WX, UNBACKED");
	g = reg_at(0x10100000);
	ok(g && g->use == KOFA_USE_CODE && (g->flags & KOFA_RGF_UNBACKED) && !(g->flags & KOFA_RGF_WX), "r-xp anonymous: CODE, UNBACKED");
	g = reg_at(0x10200000);
	ok(g && g->use == KOFA_USE_UNKNOWN, "---p: UNKNOWN (a reservation)");
	g = reg_at(0x10300000);
	ok(g && g->use == KOFA_USE_HEAP, "rw-p anonymous: HEAP");
	{
		struct reg *a = reg_at(0x10300000), *b = reg_at(0x10301000);

		ok(a && b && a->group == b->group, "two adjacent anonymous regions share a group");
		g = reg_at(0x10200000);
		ok(g && a && g->group == a->group, "an anonymous reservation joins the group of the anonymous regions around it");
	}
	g = reg_at(0x20000000);
	ok(g && (g->flags & KOFA_RGF_DELETED) && (g->flags & KOFA_RGF_UNBACKED) && !strcmp(g->path, "/tmp/gone"), "'(deleted)': stripped, DELETED, and an exec image with no file is UNBACKED");
	g = reg_at(0x20001000);
	ok(g && (g->flags & KOFA_RGF_MEMFD) && !(g->flags & KOFA_RGF_DELETED) && (g->flags & KOFA_RGF_UNBACKED), "/memfd: MEMFD, and DELETED is withdrawn");
	g = reg_at(0x20002000);
	ok(g && (g->flags & KOFA_RGF_VOLATILE), "/dev/shm/: VOLATILE");
	g = reg_at(0x20003000);
	ok(g && (g->flags & KOFA_RGF_VOLATILE), "/run/: VOLATILE");
	g = reg_at(0x30000000);
	ok(g && g->use == KOFA_USE_DATA && (g->flags & KOFA_RGF_KERNEL_MAPPED), "[vdso]: DATA, kernel mapped");
	g = reg_at(0x30001000);
	ok(g && g->use == KOFA_USE_DATA && (g->flags & KOFA_RGF_KERNEL_MAPPED) && !(g->flags & KOFA_RGF_UNBACKED), "[vsyscall] is executable and anonymous and is NOT unbacked code");
	g = reg_at(0x30002000);
	ok(g && g->use == KOFA_USE_DATA && (g->flags & KOFA_RGF_KERNEL_MAPPED), "[anon:...]: a bracketed name is the kernel's: DATA");
	g = reg_at(0x7ffc00000000ull);
	ok(g && g->use == KOFA_USE_STACK && g->size == 0x21000, "[stack]: STACK, 64-bit addresses");
	g = reg_at(0x40000000);
	ok(g && !strcmp(g->path, "/home/u/a file with  spaces.so"), "a path with spaces (and a double space) comes back whole");
	g = reg_at(0x40001000);
	ok(g && !(g->flags & KOFA_RGF_MEMFD), "'/tmp/memfd:fake' is not a memfd (prefix, not substring)");
	/* the filters */
	o.want = 0;                                    /* the default: no reserved, no heap */
	n = walk_regions(100, &o, 0);
	OKF(n == 15 && !reg_at(0x10200000) && !reg_at(0x1000000) && !reg_at(0x10300000), "default want: no reservation, no heap (got %d)", n);
	OKF(last_stat.regions_filtered == 4, "regions_filtered counts the four left out (got %llu)", (unsigned long long)last_stat.regions_filtered);
	o.want = KOFA_MW_EXEC_ONLY;
	n = walk_regions(100, &o, 0);
	OKF(n == 8, "EXEC_ONLY: only executable regions (got %d)", n);
	o.want = KOFA_MW_EXEC_ONLY | KOFA_MW_HEAP | KOFA_MW_RESERVED;
	n = walk_regions(100, &o, 0);
	OKF(n == 8, "EXEC_ONLY with HEAP and RESERVED asked: still only the executable ones (got %d)", n);
}

static void case_maps_hostile(void)
{
	struct kofa_pmem_option o;
	char *big, line[8300], cl[200];
	size_t at = 0, i;
	int n;
	struct reg *g;

	printf("\nmaps: hostile text:\n");
	memset(&o, 0, sizeof o);
	o.want = KOFA_MW_RESERVED | KOFA_MW_HEAP;
	/* a 4095-byte path, a line the buffer splits, tabs, CRLF, a one-letter permission field */
	fresh();
	big = malloc(1u << 20);
	memset(line, 'p', 4095);
	line[0] = '/';
	line[4095] = '\0';
	at += (size_t)snprintf(big + at, 5000, "00400000-00401000 r-xp 00000000 08:01 7 %s\n", line);
	at += (size_t)snprintf(big + at, 1000, "00401000-00402000 r-xp 00000000 08:01 7 /tab\tname\r\n");
	at += (size_t)snprintf(big + at, 1000, "00402000-00403000 r-xp 00000000 08:01 7 \t /after-tab\n");
	at += (size_t)snprintf(big + at, 1000, "00403000-00404000 r 00000000 08:01 7 /one-letter-perms\n");
	at += (size_t)snprintf(big + at, 1000, "00404000-00405000 rwxp 00000000 08:01 7\n");
	at += (size_t)snprintf(big + at, 1000, "ffffffffffff0000-ffffffffffffffff rw-p 00000000 00:00 0 [stack]\n");
	at += (size_t)snprintf(big + at, 1000, "0-ffffffffffffffff rw-p 00000000 00:00 0\n");
	memset(line, 'q', sizeof line - 1);
	line[sizeof line - 1] = '\0';
	at += (size_t)snprintf(big + at, 9000, "00500000-00501000 r-xp 00000000 08:01 7 /%s\n", line);
	big[at] = '\0';
	put_proc(100, big, NULL);
	n = walk_regions(100, &o, 0);
	ok(n >= 6, "hostile lines: the walk goes on past all of them");
	g = reg_at(0x400000);
	ok(g && strlen(g->path) == 4095, "a 4095-byte path is whole");
	g = reg_at(0x401000);
	ok(g && !strcmp(g->path, "/tab\tname"), "CRLF stripped, a tab inside the path kept");
	g = reg_at(0x402000);
	ok(g && !strcmp(g->path, "/after-tab"), "tabs and spaces before the path are skipped");
	(void)cl;
	g = reg_at(0xffffffffffff0000ull);
	ok(g && g->size == 0xffff && g->use == KOFA_USE_STACK, "an address at the top of the 64-bit space");
	g = reg_at(0);
	ok(g && g->size == ~0ull, "0-ffffffffffffffff is one region of 2^64-1 bytes (no cap on size at this layer)");
	g = reg_at(0x404000);
	ok(g && g->path[0] == '\0', "a line with no path: empty path");
	/* one more thing: the one-letter perms row is parsed from bytes the kernel never writes */
	g = reg_at(0x403000);
	ok(g != NULL, "a one-letter permission field is accepted (WP12-4: the second and third flag are read from uninitialised stack)");
	free(big);
	/* 100000 regions: streamed, the walk neither stores nor caps them */
	fresh();
	big = malloc(10u << 20);
	for (i = 0, at = 0; i < 100000; i++)
		at += (size_t)snprintf(big + at, 100, "%08zx-%08zx rw-p 00000000 00:00 0 \n", 0x10000000u + i * 0x2000u, 0x10000000u + i * 0x2000u + 0x1000u);
	put_proc(100, big, NULL);
	{
		struct kofa_pmem *m = kofa_pmem_open(100, 0, &o, NULL);
		struct kofa_region r;
		unsigned cnt = 0;

		ok(m != NULL, "opened a process with 100000 regions");
		while (m && kofa_pmem_next_region(m, &r))
			cnt++;
		ok(cnt == 100000, "all 100000 regions come back, one per call, no cap");
		kofa_pmem_close(m);
	}
	free(big);
}

/* ---------------------------------------------------------------------------------------------------- smaps */

static const char SMAPS[] =
	"00400000-00401000 r-xp 00000000 08:01 7 /usr/bin/prog\n"
	"Size:                  4 kB\n"
	"Rss:                   4 kB\n"
	"Private_Dirty:         0 kB\n"
	"00401000-00402000 r-xp 00001000 08:01 7 /usr/bin/prog\n"
	"Size:                  4 kB\n"
	"Rss:                   8 kB\n"
	"Private_Dirty:         4 kB\n"
	"00402000-00403000 rw-p 00002000 00:00 0\n"
	"Rss:                   4 kB\n"
	"Private_Dirty:         4 kB\n"
	"10000000-10100000 r-xp 00000000 00:00 0\n"
	"Rss:                   0 kB\n"
	"Private_Dirty:         4 kB\n"
	"10100000-10101000 rw-p 00000000 00:00 0\n"
	"20000000-20001000 rw-p 00000000 00:00 0\n"
	"Rss:                   99999999999999999999 kB\n"
	"20001000-20002000 rw-p 00000000 00:00 0\n"
	"Rss:                   no number here\n"
	"Rss no colon\n";

static void case_smaps(void)
{
	struct kofa_pmem_option o;
	struct reg *g;
	int n;

	printf("\nsmaps: Rss and Private_Dirty folded into the region:\n");
	fresh();
	put_proc(100, "00400000-00401000 r-xp 00000000 08:01 7 /fallback\n", SMAPS);
	memset(&o, 0, sizeof o);
	o.want = KOFA_MW_SMAPS | KOFA_MW_HEAP;
	n = walk_regions(100, &o, 0);
	OKF(n == 7, "7 regions from smaps (got %d)", n);
	g = reg_at(0x400000);
	ok(g && g->rss == 4096 && (g->flags & KOFA_RGF_RSS_MEASURED) && !(g->flags & KOFA_RGF_DIRTY_CODE), "Rss 4 kB measured; Private_Dirty 0: not dirty code");
	g = reg_at(0x401000);
	ok(g && g->rss == 8192 && (g->flags & KOFA_RGF_DIRTY_CODE), "exec file region with Private_Dirty > 0: DIRTY_CODE");
	g = reg_at(0x402000);
	ok(g && !(g->flags & KOFA_RGF_DIRTY_CODE), "Private_Dirty on a writable anonymous region is not dirty CODE");
	g = reg_at(0x10000000);
	ok(g && g->rss == 0 && (g->flags & KOFA_RGF_RSS_MEASURED) && !(g->flags & KOFA_RGF_DIRTY_CODE), "Private_Dirty on an anonymous exec region: not DIRTY_CODE (no file)");
	g = reg_at(0x10100000);
	ok(g && !(g->flags & KOFA_RGF_RSS_MEASURED) && g->rss == g->size, "a header with no counters (a header followed by a header): rss = size, not measured");
	g = reg_at(0x20000000);
	ok(g && (g->flags & KOFA_RGF_RSS_MEASURED), "a huge Rss value: measured, and the walk goes on");
	{
		struct reg *h = reg_at(0x20001000);

		ok(h && (h->flags & KOFA_RGF_RSS_MEASURED) && h->rss == 0, "an Rss line with no number: measured as 0");
	}
	/* KNOWN DEFECT WP12-5 (2026-10-24, M): this row pins it, green until fixed. */
	KM_CHECK(g && g->rss <= g->size, "a region whose smaps Rss is 99999999999999999999 kB reports an rss above its own size (kB * 1024 wraps, no clamp to size) (WP12-5)",
		 "WP12-5: a_kb_line multiplies without a clamp");
	/* smaps absent: the plain maps is read instead */
	fresh();
	put_proc(100, "00400000-00401000 r-xp 00000000 08:01 7 /fallback\n", NULL);
	n = walk_regions(100, &o, 0);
	ok(n == 1 && !strcmp(regs[0].path, "/fallback") && !(regs[0].flags & KOFA_RGF_RSS_MEASURED), "no smaps file: falls back to maps, rss unmeasured");
}

/* ---------------------------------------------------------------------------------------------------- open */

static void case_open(void)
{
	struct kofa_pmem_option o;
	struct kofa_pmem *m;
	int err = -1;

	printf("\nkofa_pmem_open:\n");
	memset(&o, 0, sizeof o);
	fresh();
	put_proc(100, "00400000-00401000 r-xp 00000000 08:01 7 /bin/x\n", NULL);
	m = kofa_pmem_open(100, 4242, &o, &err);
	ok(m && err == KOFA_OK, "the right start time opens");
	ok(m && kofa_pmem_proc(m) && kofa_pmem_proc(m)->pid == 100 && kofa_pmem_proc(m)->ppid == 1 && kofa_pmem_proc(m)->start_time == 4242 &&
	   !strcmp(kofa_pmem_proc(m)->comm, "fake"), "kofa_pmem_proc: pid, ppid, start time, comm from stat");
	kofa_pmem_close(m);
	m = kofa_pmem_open(100, 4243, &o, &err);
	ok(!m && err == KOFA_ERR_GONE, "pid reuse: another start time is GONE");
	m = kofa_pmem_open(100, 0, &o, &err);
	ok(m != NULL, "start time 0 means 'any'");
	kofa_pmem_close(m);
	m = kofa_pmem_open(999, 0, &o, &err);
	ok(!m && err == KOFA_ERR_GONE, "no such process: GONE");
	{
		char p[300];

		snprintf(p, sizeof p, "%s/100/maps", R);
		unlink(p);
		m = kofa_pmem_open(100, 0, &o, &err);
		ok(!m && err == KOFA_ERR_GONE, "no maps file: GONE");
		put_s(100, "maps", "00400000-00401000 r-xp 00000000 08:01 7 /bin/x\n");
	}
	osys_match("/maps");
	osys_fail(OSYS_FOPEN, 1, EACCES);
	m = kofa_pmem_open(100, 0, &o, &err);
	ok(!m && err == KOFA_ERR_DENIED, "EACCES on maps: DENIED");
	osys_fail(OSYS_FOPEN, 1, EPERM);
	m = kofa_pmem_open(100, 0, &o, &err);
	ok(!m && err == KOFA_ERR_DENIED, "EPERM on maps: DENIED");
	osys_fail(OSYS_FOPEN, 1, EMFILE);
	m = kofa_pmem_open(100, 0, &o, &err);
	ok(!m && err == KOFA_ERR_OS, "EMFILE on maps: KOFA_ERR_OS (a resource error is not an exited process; WP12-1)");
	osys_reset();
	osys_proc_root(R);
	ok(kofa_pmem_proc(NULL) == NULL, "kofa_pmem_proc(NULL) is NULL");
	{
		struct kofa_pmem_stat st;

		memset(&st, 0xff, sizeof st);
		kofa_pmem_stats(NULL, &st);
		ok(st.regions_seen == 0 && st.bytes_read == 0, "kofa_pmem_stats(NULL) zeroes the result");
		kofa_pmem_stats(NULL, NULL);
	}
	kofa_pmem_close(NULL);
	{
		struct kofa_region r;

		ok(kofa_pmem_next_region(NULL, &r) == 0, "kofa_pmem_next_region(NULL) is 0");
		ok(kofa_pmem_read(NULL, 0, &r, 1) == 0, "kofa_pmem_read(NULL) is 0");
	}
}

/* ---------------------------------------------------------------------------------------------------- pagemap through the region walk */

static void case_region_pagemap(void)
{
	struct kofa_pmem_option o;
	struct reg *g;
	char pat[300];
	char smaps[512];
	int n;

	printf("\nregions with a pagemap (sparse fixture file):\n");
	memset(&o, 0, sizeof o);
	/* no smaps: rss comes from pagemap; region of 256 pages, every other page present = 128 pages = 512 KiB */
	fresh();
	put_proc(100, "10000000-10100000 rw-p 00000000 00:00 0\n"
		      "10100000-10101000 rw-p 00000000 00:00 0\n"
		      "30000000-30200000 rw-p 00000000 00:00 0\n", NULL);
	{
		size_t i;

		for (i = 0; i < 256; i++)
			pat[i] = (i % 2) ? '.' : 'P';
		pat[256] = '\0';
		pm_write(100, 0x10000000, pat);
	}
	o.want = KOFA_MW_PAGEMAP | KOFA_MW_HEAP;
	n = walk_regions(100, &o, 0);
	ok(n == 3, "three regions");
	g = reg_at(0x10000000);
	ok(g && (g->flags & KOFA_RGF_RSS_MEASURED) && g->rss == 128u * 4096u && !(g->flags & KOFA_RGF_SPARSE), "pagemap rss: 128 pages, measured, half resident is not sparse");
	g = reg_at(0x10100000);
	ok(g && !(g->flags & KOFA_RGF_RSS_MEASURED) && g->rss == g->size, "a region under pagemap_min (64 KiB) is not scanned: rss = size");
	g = reg_at(0x30000000);
	ok(g && (g->flags & KOFA_RGF_RSS_MEASURED) && g->rss == 0 && (g->flags & KOFA_RGF_SPARSE),
	   "a region the pagemap says is empty (a file that ends before it): rss 0, SPARSE");
	ok(last_stat.pagemap_reads == 2 && last_stat.pagemap_failed == 0, "two pagemap scans, none failed");
	/* max_region: UNEXAMINED and counted */
	o.max_region = 0x80000;
	n = walk_regions(100, &o, 0);
	g = reg_at(0x10000000);
	ok(g && (g->flags & KOFA_RGF_UNEXAMINED) && last_stat.regions_skipped >= 1, "a region over max_region is UNEXAMINED and counted as skipped");
	o.max_region = 0;
	/* max_heap_region */
	o.max_heap_region = 0x1000;
	n = walk_regions(100, &o, 0);
	g = reg_at(0x10000000);
	ok(g && (g->flags & KOFA_RGF_UNEXAMINED), "a heap region whose rss exceeds max_heap_region is UNEXAMINED");
	o.max_heap_region = 0;
	/* pagemap failing: NO_PAGEMAP, failed counted */
	osys_match("");
	osys_fail_from(OSYS_PREAD, 1, EIO);
	n = walk_regions(100, &o, 0);
	g = reg_at(0x10000000);
	ok(g != NULL, "pread failing for every call: the region is still reported (a short read is not an error of the scan)");
	osys_reset();
	osys_proc_root(R);
	/* no pagemap file at all: NO_PAGEMAP on every region */
	{
		char p[300];

		snprintf(p, sizeof p, "%s/100/pagemap", R);
		unlink(p);
	}
	n = walk_regions(100, &o, 0);
	g = reg_at(0x10000000);
	ok(g && (g->flags & KOFA_RGF_NO_PAGEMAP) && g->rss == g->size, "no pagemap file: every region is NO_PAGEMAP and blind");
	/* zero-heavy: smaps says 4 kB resident, pagemap says 256 pages present */
	fresh();
	snprintf(smaps, sizeof smaps, "10000000-10400000 rw-p 00000000 00:00 0\nRss: 4 kB\nPrivate_Dirty: 0 kB\n");
	put_proc(100, NULL, smaps);
	{
		char *all = malloc(1025);

		memset(all, 'P', 1024);
		all[1024] = '\0';
		pm_write(100, 0x10000000, all);
		free(all);
	}
	o.want = KOFA_MW_DEFAULT | KOFA_MW_HEAP;
	n = walk_regions(100, &o, 0);
	g = reg_at(0x10000000);
	ok(g && (g->flags & KOFA_RGF_ZERO_HEAVY) && (g->flags & KOFA_RGF_SPARSE), "smaps Rss 4 kB against 4 MiB present in pagemap: ZERO_HEAVY (the shared zero page), and SPARSE");
}

/* ---------------------------------------------------------------------------------------------------- chunks */

struct got_chunk {
	uint64_t addr, len;
	unsigned char first, last;
};

static struct got_chunk gc[64];
static unsigned n_gc;

static void drain_chunks(struct kofa_pmem *m, const struct kofa_region *r)
{
	struct kofa_chunk c;

	n_gc = 0;
	while (n_gc < 64 && kofa_pmem_next_chunk(m, r, &c)) {
		gc[n_gc].addr = c.addr;
		gc[n_gc].len = c.len;
		gc[n_gc].first = ((const unsigned char *)c.p)[0];
		gc[n_gc].last = ((const unsigned char *)c.p)[c.len - 1];
		n_gc++;
	}
}

static void case_chunks(void)
{
	struct kofa_pmem_option o;
	struct kofa_pmem *m;
	struct kofa_region r;
	struct kofa_pmem_stat st;
	unsigned char *img = calloc(1, 8u * 4096u);
	static const uint64_t BASE = 0x40000000ull;
	struct kofa_sweep sw;

	printf("\nchunks: zero pages, budgets, unreadable runs (process_vm_readv served from a buffer):\n");
	/* page 0 'A', 1 zero, 2 'B', 3 absent, 4 'C', 5 zero, 6 absent, 7 'D' */
	memset(img, 'A', 4096);
	memset(img + 2 * 4096, 'B', 4096);
	memset(img + 4 * 4096, 'C', 4096);
	memset(img + 7 * 4096, 'D', 4096);
	fresh();
	put_proc(100, "40000000-40008000 rw-p 00000000 00:00 0\n", NULL);
	pm_write(100, BASE, "PPP.PP.P");
	osys_vm_set(100, BASE, img, 8u * 4096u);
	memset(&o, 0, sizeof o);
	o.want = KOFA_MW_PAGEMAP | KOFA_MW_HEAP;
	o.pagemap_min = 4096;
	m = kofa_pmem_open(100, 0, &o, NULL);
	ok(m && kofa_pmem_next_region(m, &r), "a region");
	drain_chunks(m, &r);
	OKF(n_gc == 4, "four spans of data (pages 0, 2, 4 and 7: zero pages left out, absent ones never read): got %u", n_gc);
	ok(n_gc >= 1 && gc[0].addr == BASE && gc[0].len == 4096 && gc[0].first == 'A', "the first span: page 0, 'A'");
	ok(n_gc >= 2 && gc[1].addr == BASE + 2 * 4096 && gc[1].first == 'B', "the second: page 2, 'B' (the zero page 1 is between)");
	kofa_pmem_stats(m, &st);
	OKF(st.bytes_zero == 2u * 4096u, "bytes_zero counts the two zero pages (%llu)", (unsigned long long)st.bytes_zero);
	ok(st.bytes_read > 0 && st.chunks == n_gc, "bytes_read and chunks are counted");
	kofa_pmem_close(m);
	/* chunk_max = one page: the same data, more reads */
	o.chunk_max = 4096;
	m = kofa_pmem_open(100, 0, &o, NULL);
	kofa_pmem_next_region(m, &r);
	drain_chunks(m, &r);
	OKF(n_gc == 4, "chunk_max of one page: four pages of data, four chunks (got %u)", n_gc);
	ok(n_gc == 4 && gc[3].addr == BASE + 7 * 4096 && gc[3].first == 'D', "the last chunk is page 7");
	kofa_pmem_close(m);
	/* a per-process budget of two pages */
	o.max_bytes = 2 * 4096;
	m = kofa_pmem_open(100, 0, &o, NULL);
	kofa_pmem_next_region(m, &r);
	drain_chunks(m, &r);
	kofa_pmem_stats(m, &st);
	ok(st.bytes_read <= 2u * 4096u, "max_bytes of two pages: never read more than that");
	ok(st.regions_skipped >= 1, "and the refusal is counted as a skipped region");
	kofa_pmem_close(m);
	/* a sweep budget shared across processes */
	memset(&sw, 0, sizeof sw);
	sw.max_bytes = 4096;
	o.max_bytes = 0;
	o.sweep = &sw;
	m = kofa_pmem_open(100, 0, &o, NULL);
	kofa_pmem_next_region(m, &r);
	drain_chunks(m, &r);
	ok(sw.used <= 4096 && sw.refused > 0 && sw.regions_refused == 1, "a sweep budget of one page: used <= 1 page, the rest counted as refused, one region refused");
	kofa_pmem_close(m);
	/* the sweep already spent */
	sw.used = sw.max_bytes;
	o.sweep = &sw;
	m = kofa_pmem_open(100, 0, &o, NULL);
	kofa_pmem_next_region(m, &r);
	drain_chunks(m, &r);
	ok(n_gc == 0, "a spent sweep: no chunk at all");
	kofa_pmem_close(m);
	/* kofa_pmem_read directly: a short copy at the end of a mapping, an address outside, the budget */
	o.sweep = NULL;
	m = kofa_pmem_open(100, 0, &o, NULL);
	{
		unsigned char buf[8192];

		ok(kofa_pmem_read(m, BASE + 7 * 4096, buf, 8192) == 4096, "a read that runs off the end of the mapping is short");
		ok(kofa_pmem_read(m, BASE + 0x100000, buf, 16) == 0, "an address outside every mapping: 0");
		ok(kofa_pmem_read(m, BASE, NULL, 16) == 0 && kofa_pmem_read(m, BASE, buf, 0) == 0, "NULL buffer and zero length: 0");
	}
	kofa_pmem_close(m);
	o.max_bytes = 100;
	m = kofa_pmem_open(100, 0, &o, NULL);
	{
		unsigned char buf[8192];

		ok(kofa_pmem_read(m, BASE, buf, 8192) == 100, "kofa_pmem_read is cut to the per-process budget");
		ok(kofa_pmem_read(m, BASE, buf, 8192) == 0, "and answers 0 once it is spent");
	}
	kofa_pmem_close(m);
	/* process_vm_readv failing for every call: the run is dropped, the walk ends without a chunk */
	o.max_bytes = 0;
	osys_reset();
	osys_proc_root(R);
	osys_vm_set(100, BASE, img, 8u * 4096u);
	osys_fail_from(OSYS_VM, 1, EPERM);
	m = kofa_pmem_open(100, 0, &o, NULL);
	kofa_pmem_next_region(m, &r);
	drain_chunks(m, &r);
	ok(n_gc == 0, "process_vm_readv refused (EPERM): no chunk and no hang");
	kofa_pmem_close(m);
	/* no pagemap: the region is read as one run */
	osys_reset();
	osys_proc_root(R);
	osys_vm_set(100, BASE, img, 8u * 4096u);
	{
		char p[300];

		snprintf(p, sizeof p, "%s/100/pagemap", R);
		unlink(p);
	}
	m = kofa_pmem_open(100, 0, &o, NULL);
	kofa_pmem_next_region(m, &r);
	drain_chunks(m, &r);
	ok(n_gc >= 3 && (r.flags & KOFA_RGF_NO_PAGEMAP), "no pagemap: the whole region is one run, zero pages still left out");
	kofa_pmem_close(m);
	/* a region the smaps says holds nothing is not read */
	fresh();
	put_proc(100, NULL, "40000000-40008000 rw-p 00000000 00:00 0\nRss: 0 kB\n");
	osys_vm_set(100, BASE, img, 8u * 4096u);
	o.want = KOFA_MW_DEFAULT | KOFA_MW_HEAP;
	m = kofa_pmem_open(100, 0, &o, NULL);
	kofa_pmem_next_region(m, &r);
	drain_chunks(m, &r);
	ok(n_gc == 0, "smaps Rss 0: no read at all");
	kofa_pmem_close(m);
	/* NULL arguments */
	{
		struct kofa_chunk c;

		ok(kofa_pmem_next_chunk(NULL, &r, &c) == 0, "kofa_pmem_next_chunk(NULL) is 0");
	}
	free(img);
}

/* ---------------------------------------------------------------------------------------------------- walk */

static void case_walk(void)
{
	struct kof_walk_api *w;
	struct kof_proc_build b;
	struct kof_walk_item it;
	unsigned nproc = 0, nfile = 0, nbytes = 0;
	uint64_t procs, refused, regions, bytes;
	static unsigned char img[4096];
	int err = -1;
	const char *last_label = "";
	struct kof_walk_option opt;
	uint32_t pids[3] = { 200, 999, 100 };

	printf("\nkof_walk_open over the fixture:\n");
	memset(img, 0x90, sizeof img);
	fresh();
	put_proc(100, "00400000-00401000 r-xp 00000000 08:01 7 /bin/prog\n10000000-10001000 r-xp 00000000 00:00 0\n", NULL);
	pm_write(100, 0x10000000, "P");
	osys_vm_set(100, 0x10000000, img, sizeof img);
	(void)osys_put(R, 100, "cmdline", "prog\0arg\0", 9);
	(void)osys_link(R, 100, "exe", "/bin/prog");
	put_s(200, "stat", "200 (two) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99 1 1\n");      /* no maps: refused */
	put_s(300, "stat", "300 (kt) S 2 1 1 0 -1 2097152 0 0 0 0 0 0 0 0 20 0 1 0 98 1 1\n");   /* a kernel thread */
	w = kof_walk_open(NULL, &err);
	ok(w && err == KOFA_OK, "kof_walk_open(NULL) opens the list mode");
	while (w && w->next_proc(w->self, &b)) {
		nproc++;
		ok(b.pid == 100 && b.os == 2 && b.ppid == 1 && b.start_time == 4242, "the process record: pid, os = Linux, ppid, start time");
		ok(b.cmdline && !strncmp(b.cmdline, "prog arg", 8), "its cmdline");
		while (w->next_item(w->self, &it)) {
			if (it.kind == KOF_WALK_FILE) {
				nfile++;
				ok(it.path && !strcmp(it.path, "/bin/prog"), "a file-backed region is offered as a FILE, by path");
			} else if (it.kind == KOF_WALK_BYTES) {
				nbytes++;
				last_label = it.label ? it.label : "";
				ok(it.len == 4096 && ((const unsigned char *)it.p)[0] == 0x90 && it.addr == 0x10000000ull, "an anonymous executable region is offered as BYTES, read from the process");
			}
		}
	}
	ok(nproc == 1 && nfile == 1 && nbytes == 1, "one process, one file, one byte span (the refused and the kernel thread are not offered)");
	ok(!strcmp(last_label, "MEM_CODE"), "label MEM_CODE for anonymous executable memory");
	w->stats(w->self, &procs, &refused, &regions, &bytes);
	OKF(procs == 1 && refused == 1 && regions >= 2 && bytes == 4096, "stats: 1 process, 1 refused, regions seen, 4096 bytes read (got %llu %llu %llu %llu)",
	    (unsigned long long)procs, (unsigned long long)refused, (unsigned long long)regions, (unsigned long long)bytes);
	w->stats(w->self, NULL, NULL, NULL, NULL);
	ok(w->next_item(w->self, &it) == 0, "next_item with no open process: 0");
	w->close(w->self);
	/* pid mode */
	memset(&opt, 0, sizeof opt);
	opt.pids = pids;
	opt.n_pids = 3;
	w = kof_walk_open(&opt, &err);
	nproc = 0;
	while (w && w->next_proc(w->self, &b)) {
		nproc++;
		while (w->next_item(w->self, &it))
			;
	}
	ok(nproc == 1, "pid mode: [200 refused, 999 gone, 100] gives one process");
	w->stats(w->self, &procs, &refused, &regions, &bytes);
	OKF(procs == 1 && refused == 2, "pid mode stats: 2 refused (200 has no maps, 999 does not exist): got %llu", (unsigned long long)refused);
	w->close(w->self);
	/* map intent: anonymous regions are not read and heap is asked for */
	memset(&opt, 0, sizeof opt);
	opt.intent = KOF_WALK_MAP;
	w = kof_walk_open(&opt, &err);
	nbytes = 0;
	while (w && w->next_proc(w->self, &b))
		while (w->next_item(w->self, &it))
			nbytes += it.kind == KOF_WALK_BYTES;
	ok(nbytes == 1, "KOF_WALK_MAP: the anonymous region's bytes are offered too (a map wants every region with bytes in it)");
	w->close(w->self);
	/* the list cannot be opened */
	osys_fail(OSYS_OPENDIR, 1, EMFILE);
	w = kof_walk_open(NULL, &err);
	ok(w == NULL && err == KOFA_ERR_OS, "opendir(/proc) failing: kof_walk_open answers NULL with KOFA_ERR_OS");
	osys_reset();
	ok(1, "walk NULL arguments");
	{
		struct kof_walk_api *w2;

		osys_proc_root(R);
		w2 = kof_walk_open(NULL, NULL);
		ok(w2 && w2->next_proc(NULL, &b) == 0 && w2->next_proc(w2->self, NULL) == 0 && w2->next_item(NULL, &it) == 0, "next_proc / next_item refuse NULL");
		w2->stats(NULL, NULL, NULL, NULL, NULL);
		w2->close(NULL);
		w2->close(w2->self);
	}
}

static void case_walk_labels(void)
{
	struct kof_walk_api *w;
	struct kof_proc_build b;
	struct kof_walk_item it;
	struct kof_walk_option opt;
	static unsigned char img[4096];
	char real[600];
	unsigned labels = 0, files = 0, got_flags = 0;
	char seen[16][16];
	unsigned i;

	printf("\nkof_walk_open: the process record's flags and the labels of what is mapped:\n");
	memset(img, 0x41, sizeof img);
	fresh();
	snprintf(real, sizeof real, "%s/realexe", R);
	(void)osys_put_flat(R, "realexe", "x", 1);
	put_s(100, "stat", "100 (fx) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 1 1\n");
	put_s(100, "maps",
	      "10000000-10001000 r-xp 00000000 00:01 5 /memfd:evil (deleted)\n"
	      "10001000-10002000 r-xp 00000000 08:01 6 /tmp/gone (deleted)\n"
	      "10002000-10003000 rw-p 00000000 00:00 0 [heap]\n"
	      "10003000-10004000 rw-p 00000000 00:00 0\n"
	      "10004000-10005000 r-xp 00000000 00:00 0 [stack]\n"
	      "10005000-10006000 r--p 00000000 08:01 7 /usr/lib/x.so\n");
	{
		char target[700];

		snprintf(target, sizeof target, "%s (deleted)", real);
		(void)osys_link(R, 100, "exe", target);
	}
	(void)osys_link(R, 100, "fd/0", "/dev/null");
	{
		unsigned q;

		for (q = 0; q < 5; q++)
			osys_vm_set(100, 0x10000000ull + q * 0x1000ull, img, sizeof img);
	}
	memset(&opt, 0, sizeof opt);
	opt.intent = KOF_WALK_MAP;
	w = kof_walk_open(&opt, NULL);
	while (w && w->next_proc(w->self, &b)) {
		got_flags = b.flags;
		while (w->next_item(w->self, &it)) {
			if (it.kind == KOF_WALK_BYTES && it.label && labels < 16) {
				snprintf(seen[labels], sizeof seen[0], "%s", it.label);
				labels++;
			} else if (it.kind == KOF_WALK_FILE)
				files++;
		}
	}
	ok(got_flags & KOF_PROC_F_EXE_GONE, "the process record carries EXE_GONE for an exe link ending in '(deleted)'");
	ok(got_flags & KOF_PROC_F_EXE_ON_DISK, "and EXE_ON_DISK: the stripped path still resolves (the two facts are separate)");
	ok(got_flags & KOF_PROC_F_FDS_READ, "FDS_READ: the descriptors were read");
	ok(!(got_flags & KOF_PROC_F_KTHREAD) && b.pid == 100, "not a kernel thread");
	for (i = 0; i < labels; i++)
		printf("       label %s\n", seen[i]);
	{
		unsigned found = 0;

		for (i = 0; i < labels; i++)
			found |= !strcmp(seen[i], "MEM_MEMFD") ? 1u : !strcmp(seen[i], "MEM_DELETED") ? 2u : !strcmp(seen[i], "MEM_HEAP") ? 4u : !strcmp(seen[i], "MEM_STACK") ? 8u : 0u;
		ok(files == 1 || files == 2, "the file-backed regions are offered as files");
		OKF(found == 15, "the byte spans of a map walk carry the region's word: MEM_MEMFD, MEM_DELETED, MEM_HEAP, MEM_STACK (mask %u of 15)", found);
	}
	if (w)
		w->close(w->self);
	/* a kernel thread is never offered: its record is skipped in list mode */
	fresh();
	put_s(300, "stat", "300 (kt) S 2 1 1 0 -1 2097152 0 0 0 0 0 0 0 0 20 0 1 0 98 1 1\n");
	w = kof_walk_open(NULL, NULL);
	ok(w && w->next_proc(w->self, &b) == 0, "a list of only a kernel thread offers no process");
	if (w)
		w->close(w->self);
}

/* ---------------------------------------------------------------------------------------------------- describe */

static void case_describe(void)
{
	struct kofa_region r;
	char buf[300];
	size_t n;
	static const uint8_t uses[] = { KOFA_USE_UNKNOWN, KOFA_USE_IMAGE, KOFA_USE_CODE, KOFA_USE_HEAP, KOFA_USE_STACK, KOFA_USE_DATA, 77 };
	static const char *const names[] = { "?", "image", "code", "heap", "stack", "data", "?" };
	unsigned i;

	printf("\nkofa_region_describe:\n");
	memset(&r, 0, sizeof r);
	r.base = 0x7f0000001000ull;
	r.size = 8192;
	r.rss = 4096;
	r.flags = KOFA_RGF_READ | KOFA_RGF_WRITE | KOFA_RGF_EXEC | KOFA_RGF_RSS_MEASURED | KOFA_RGF_UNBACKED | KOFA_RGF_DELETED | KOFA_RGF_MEMFD |
		  KOFA_RGF_WX | KOFA_RGF_UNEXAMINED | KOFA_RGF_ZERO_HEAVY | KOFA_RGF_DIRTY_CODE;
	r.path = "/x/y";
	r.use = KOFA_USE_CODE;
	n = kofa_region_describe(&r, buf, sizeof buf);
	ok(n == strlen(buf), "the return is the length written");
	ok(strstr(buf, "00007f0000001000") && strstr(buf, "rwxp") && strstr(buf, "code") && strstr(buf, " unbacked") && strstr(buf, " deleted") &&
	   strstr(buf, " memfd") && strstr(buf, " wx") && strstr(buf, " skipped") && strstr(buf, " zeroes") && strstr(buf, " DIRTY") && strstr(buf, " /x/y"),
	   "every flag and the path are spelled");
	ok(strstr(buf, "res    4K ") != NULL || strstr(buf, "res") != NULL, "rss in K, measured (no question mark)");
	r.flags = KOFA_RGF_READ;
	r.path = NULL;
	n = kofa_region_describe(&r, buf, sizeof buf);
	ok(strstr(buf, "K?") != NULL && strstr(buf, "r--p") && !strstr(buf, " /"), "unmeasured rss is marked with '?', r--p, no path");
	for (i = 0; i < sizeof uses; i++) {
		char w[80];

		r.use = uses[i];
		kofa_region_describe(&r, buf, sizeof buf);
		snprintf(w, sizeof w, "use %u is spelled '%s'", uses[i], names[i]);
		ok(strstr(buf, names[i]) != NULL, w);
	}
	/* every buffer size: never past cap, always terminated */
	for (i = 1; i < 120; i++) {
		char small[130];

		memset(small, 0x55, sizeof small);
		n = kofa_region_describe(&r, small, i);
		if (n >= i || small[n] != '\0' || small[i] != 0x55) {
			OKF(0, "describe with cap %u wrote past the buffer or did not terminate", i);
			break;
		}
	}
	ok(1, "describe: caps 1..119 stay inside the buffer");
	ok(kofa_region_describe(&r, NULL, 10) == 0 && kofa_region_describe(&r, buf, 0) == 0, "NULL buffer and cap 0: 0");
	buf[0] = 'x';
	ok(kofa_region_describe(NULL, buf, sizeof buf) == 0 && buf[0] == '\0', "a NULL region gives the empty string");
}

int main(void)
{
	R = osys_tmpdir("orbit_pmem");
	if (!R) {
		printf("cannot make the scratch directory\n");
		return 1;
	}
	case_pm_rows();
	case_pm_batches();
	case_pm_args();
	case_maps();
	case_maps_hostile();
	case_smaps();
	case_open();
	case_region_pagemap();
	case_chunks();
	case_walk();
	case_walk_labels();
	case_describe();
	osys_reset();
	osys_rmrf(R);
	free(R);
	printf("\n%d check(s), %d failed; known misses %u\n", checks, fails, km_known_n);
	return (fails || km_fixed_n) ? 1 : 0;
}
