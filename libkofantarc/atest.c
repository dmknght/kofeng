/* SPDX-License-Identifier: Apache-2.0 */
/*
 * atest - drive libkofantarc's snapshot half and print what it found.
 *
 * TEMPORARY. It exists so the walk can be run and checked against the
 * measurements in PLAN.md before kofmemscan is touched - that file is shared
 * with the Windows collector and is being edited elsewhere. It goes away when
 * the walk is wired into kofmemscan.
 *
 *   atest              summary over every readable process
 *   atest -v           one line per interesting region
 *   atest -p <pid>     one process, every region
 *   atest --heap       include heap regions, capped
 *   atest --blind      no pagemap, to measure what it saves
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aproc.h"

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

struct total {
	uint64_t procs, refused, regions, filtered, skipped;
	uint64_t virt, res, unmeasured, read, measured;
	uint64_t code_regions, code_virt, code_res;
	uint64_t heap_regions, heap_res;
	uint64_t deleted, memfd, wx, sparse;
	uint64_t pm_reads, pm_failed;
};

static void do_proc(uint32_t pid, uint64_t start, int verbose, uint32_t want,
		    struct total *t)
{
	struct kofa_pmem_option po;
	struct kofa_pmem *m;
	struct kofa_region r;
	struct kofa_pmem_stat st;
	int err = 0;

	memset(&po, 0, sizeof po);
	po.want = want;

	m = kofa_pmem_open(pid, start, &po, &err);
	if (!m) {
		if (err == KOFA_ERR_DENIED)
			t->refused++;
		return;
	}

	t->procs++;

	while (kofa_pmem_next_region(m, &r)) {
		if (r.flags & KOFA_RGF_DELETED)   t->deleted++;
		if (r.flags & KOFA_RGF_MEMFD)     t->memfd++;
		if (r.flags & KOFA_RGF_WX)        t->wx++;
		if (r.flags & KOFA_RGF_SPARSE)    t->sparse++;

		if (r.use == KOFA_USE_CODE) {
			t->code_regions++;
			t->code_virt += r.size;
			t->code_res  += r.rss;
		} else if (r.use == KOFA_USE_HEAP) {
			t->heap_regions++;
			t->heap_res += r.rss;
		}

		if (verbose &&
		    (r.use == KOFA_USE_CODE ||
		     (r.flags & (KOFA_RGF_DELETED | KOFA_RGF_MEMFD)))) {
			char line[512];

			kofa_region_describe(&r, line, sizeof line);
			printf("  [%u %s] %s\n", pid,
			       kofa_pmem_proc(m)->comm, line);
		}
	}

	kofa_pmem_stats(m, &st);
	t->regions  += st.regions_seen;
	t->filtered += st.regions_filtered;
	t->skipped  += st.regions_skipped;
	t->virt     += st.bytes_virtual;
	t->res      += st.bytes_resident;
	t->unmeasured += st.bytes_unmeasured;
	t->measured += st.regions_measured;
	t->read     += st.bytes_read;
	t->pm_reads += st.pagemap_reads;
	t->pm_failed += st.pagemap_failed;

	kofa_pmem_close(m);
}

int main(int argc, char **argv)
{
	struct total t;
	uint32_t want = KOFA_MW_DEFAULT;
	int verbose = 0, one = 0, i;
	double t0;

	memset(&t, 0, sizeof t);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v"))
			verbose = 1;
		else if (!strcmp(argv[i], "--heap"))
			want |= KOFA_MW_HEAP;
		else if (!strcmp(argv[i], "--blind"))
			want &= ~(uint32_t)KOFA_MW_PAGEMAP;
		else if (!strcmp(argv[i], "-p") && i + 1 < argc)
			one = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--exec"))
			want |= KOFA_MW_EXEC_ONLY;
		else {
			fprintf(stderr, "usage: %s [-v] [-p pid] [--heap] "
					"[--exec] [--blind]\n", argv[0]);
			return 2;
		}
	}

	t0 = now();

	if (one) {
		do_proc((uint32_t)one, 0, 1, want, &t);
	} else {
		struct kofa_plist *l;
		struct kofa_proc p;
		int err = 0;

		l = kofa_plist_open(NULL, &err);
		if (!l) {
			fprintf(stderr, "plist: %s\n", kofa_err_name(err));
			return 1;
		}
		while (kofa_plist_next(l, &p)) {
			if (p.flags & KOFA_PF_REFUSED) {
				t.refused++;
				continue;
			}
			/*
			 * Only the strong forms. STDIO_SOCKET alone is eight
			 * legitimate processes on this desktop and printing it
			 * teaches a reader to skip the list.
			 */
			if (p.flags & (KOFA_PF_EXE_MEMFD |
				       KOFA_PF_EXE_UNLINKED |
				       KOFA_PF_FAKE_KTHREAD |
				       KOFA_PF_STDIO_SAME_SOCKET)) {
				printf("  ! pid %-7u %-14s%s%s%s%s%s%s\n",
				       p.pid, p.comm,
				       (p.flags & KOFA_PF_EXE_MEMFD)
					       ? " MEMFD" : "",
				       (p.flags & KOFA_PF_EXE_UNLINKED)
					       ? " SELF-DELETED" : "",
				       (p.flags & KOFA_PF_FAKE_KTHREAD)
					       ? " FAKE-KTHREAD" : "",
				       (p.flags & KOFA_PF_STDIO_SAME_SOCKET)
					       ? " SAME-SOCKET" : "",
				       (p.flags & KOFA_PF_SHELL)
					       ? " SHELL" : "",
				       (p.flags & KOFA_PF_STDIO_ONLY)
					       ? " STDIO-ONLY" : "");
				printf("      exe %s\n", p.exe);
				printf("      cmd %.110s\n", p.cmdline);
				printf("      fd0 %s\n      fd1 %s\n",
				       p.fd_stdin, p.fd_stdout);
				printf("      fds %u (%u socket)\n",
				       p.n_fd, p.n_socket);
			}
			do_proc(p.pid, p.start_time, verbose, want, &t);
		}
		kofa_plist_close(l);
	}

	printf("\n");
	printf("processes walked   : %llu  (%llu refused)\n",
	       (unsigned long long)t.procs, (unsigned long long)t.refused);
	printf("regions reported   : %llu  (%llu filtered, %llu unexamined)\n",
	       (unsigned long long)t.regions, (unsigned long long)t.filtered,
	       (unsigned long long)t.skipped);
	printf("  virtual          : %.1f MB\n", t.virt / 1048576.0);
	printf("  RESIDENT         : %.1f MB  over %llu measured regions\n",
	       t.res / 1048576.0, (unsigned long long)t.measured);
	printf("  unmeasured       : %.1f MB  (upper bound, %llu regions)\n",
	       t.unmeasured / 1048576.0,
	       (unsigned long long)(t.regions - t.measured));
	printf("\n");
	printf("unbacked code      : %llu regions, %.1f MB virt -> %.2f MB res\n",
	       (unsigned long long)t.code_regions, t.code_virt / 1048576.0,
	       t.code_res / 1048576.0);
	printf("heap               : %llu regions, %.1f MB res\n",
	       (unsigned long long)t.heap_regions, t.heap_res / 1048576.0);
	printf("deleted / memfd    : %llu / %llu\n",
	       (unsigned long long)t.deleted, (unsigned long long)t.memfd);
	printf("rwx / sparse       : %llu / %llu\n",
	       (unsigned long long)t.wx, (unsigned long long)t.sparse);
	printf("pagemap reads      : %llu  (%llu failed)\n",
	       (unsigned long long)t.pm_reads,
	       (unsigned long long)t.pm_failed);
	printf("\nwalk took %.1f ms\n", (now() - t0) * 1e3);
	return 0;
}
