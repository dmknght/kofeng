/* SPDX-License-Identifier: Apache-2.0 */
/*
 * atest_unit - guard the four things that actually broke.
 *
 * TEMPORARY, like atest.c: this moves to tests/unit/ when the Makefile is
 * touched, which is waiting on the libkofgrille session.
 *
 * Every case here is a bug that was real, not a hypothetical. Three were found
 * by running the walk and comparing it against /proc by hand, and the fourth is
 * the /proc/<pid>/stat parser trap that every implementation of this hits once.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "aproc.h"

static int fails;

static void ok(int cond, const char *what)
{
	printf("  %-4s %s\n", cond ? "ok" : "FAIL", what);
	if (!cond)
		fails++;
}

/*
 * A PROCESS NAMED ") 1 2 3 (".
 *
 * /proc/<pid>/stat is "<pid> (<comm>) <state> <ppid> ...". comm is not escaped
 * and may hold spaces and parentheses, so splitting on whitespace reads the
 * state field as the ppid for exactly those processes - and an attacker picks
 * the name. The only correct split is at the LAST ')'.
 */
static void test_comm_trap(void)
{
	int fd[2];
	pid_t kid;
	unsigned long base = 0;

	printf("\ncomm with parentheses and spaces:\n");

	if (pipe(fd))
		return;

	kid = fork();
	if (kid == 0) {
		close(fd[0]);
		prctl(PR_SET_NAME, ") 1 2 3 (x", 0, 0, 0);
		write(fd[1], &base, sizeof base);
		pause();
		_exit(0);
	}
	close(fd[1]);
	read(fd[0], &base, sizeof base);
	usleep(100000);

	{
		struct kofa_pmem *m;
		int err = 0;

		m = kofa_pmem_open((uint32_t)kid, 0, NULL, &err);
		ok(m != NULL, "opened the process");
		if (m) {
			const struct kofa_proc *p = kofa_pmem_proc(m);

			ok(p->ppid == (uint32_t)getpid(),
			   "ppid is the test, not a field of the name");
			ok(p->start_time != 0, "start_time parsed");
			ok(strcmp(p->comm, ") 1 2 3 (x") == 0,
			   "comm came back whole");
			kofa_pmem_close(m);
		}
	}

	kill(kid, 9);
	waitpid(kid, NULL, 0);
}

/*
 * PROT_NONE IS A RESERVATION AND MUST NOT BE COUNTED.
 *
 * Chromium reserves 1.3 TB of it per process. The first walk summed those and
 * reported ten terabytes resident on a sixteen gigabyte machine.
 */
static void test_prot_none(void)
{
	int fd[2];
	pid_t kid;
	unsigned long base = 0;
	const size_t RESERVE = 256u << 20;   /* 256 MB, PROT_NONE */

	printf("\nPROT_NONE reservation:\n");

	if (pipe(fd))
		return;

	kid = fork();
	if (kid == 0) {
		void *m = mmap(NULL, RESERVE, PROT_NONE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
			       -1, 0);

		close(fd[0]);
		base = (unsigned long)(uintptr_t)m;
		write(fd[1], &base, sizeof base);
		pause();
		_exit(0);
	}
	close(fd[1]);
	read(fd[0], &base, sizeof base);
	usleep(100000);

	{
		struct kofa_pmem *m;
		struct kofa_region r;
		struct kofa_pmem_stat st;
		int err = 0, saw_it = 0;

		m = kofa_pmem_open((uint32_t)kid, 0, NULL, &err);
		if (m) {
			while (kofa_pmem_next_region(m, &r))
				if (r.base == base)
					saw_it = 1;
			kofa_pmem_stats(m, &st);
			ok(!saw_it, "the reservation was filtered out");
			ok(st.bytes_virtual < RESERVE,
			   "it was not summed into bytes_virtual");
			kofa_pmem_close(m);
		}

		/* And it IS reported when asked for. */
		{
			struct kofa_pmem_option o;

			memset(&o, 0, sizeof o);
			o.want = KOFA_MW_DEFAULT | KOFA_MW_RESERVED;
			saw_it = 0;
			m = kofa_pmem_open((uint32_t)kid, 0, &o, &err);
			if (m) {
				while (kofa_pmem_next_region(m, &r))
					if (r.base == base &&
					    r.use == KOFA_USE_UNKNOWN)
						saw_it = 1;
				ok(saw_it,
				   "KOFA_MW_RESERVED brings it back");
				kofa_pmem_close(m);
			}
		}
	}

	kill(kid, 9);
	waitpid(kid, NULL, 0);
}

/*
 * rss COMES FROM smaps, NOT FROM pagemap, because a page that anything has
 * READ is PRESENT in pagemap while holding the shared zero page.
 *
 * The child writes a little and reserves a lot; the test then reads the whole
 * mapping out of it, which is exactly what a blind scanner does, and checks
 * that rss did not follow.
 */
static void test_zero_page(void)
{
	int fd[2];
	pid_t kid;
	unsigned long base = 0;
	const size_t SIZE = 64u << 20;
	const size_t TOUCHED = 16u << 12;    /* 16 pages written */

	printf("\nrss survives a blind read (shared zero page):\n");

	if (pipe(fd))
		return;

	kid = fork();
	if (kid == 0) {
		char *m = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		size_t i;

		close(fd[0]);
		if (m == MAP_FAILED)
			_exit(1);
		for (i = 0; i < TOUCHED; i += 4096)
			m[i] = 'A';
		base = (unsigned long)(uintptr_t)m;
		write(fd[1], &base, sizeof base);
		pause();
		_exit(0);
	}
	close(fd[1]);
	read(fd[0], &base, sizeof base);
	usleep(150000);

	{
		struct kofa_pmem *m;
		struct kofa_region r;
		struct kofa_pmem_option o;
		uint64_t before = 0, after = 0;
		int err = 0;
		char *buf;

		/*
		 * The mapping under test is anonymous, writable and not
		 * executable, which is KOFA_USE_HEAP - filtered out by
		 * default. Asking for it explicitly is the point: the default
		 * being right is what the rest of this file measures.
		 */
		memset(&o, 0, sizeof o);
		o.want = KOFA_MW_DEFAULT | KOFA_MW_HEAP;
		o.max_heap_region = SIZE;

		m = kofa_pmem_open((uint32_t)kid, 0, &o, &err);
		if (m) {
			while (kofa_pmem_next_region(m, &r))
				if (base >= r.base &&
				    base < r.base + r.size) {
					before = r.rss;
					printf("       region %llx+%lluK "
					       "rss=%lluK\n",
					       (unsigned long long)r.base,
					       (unsigned long long)(r.size>>10),
					       (unsigned long long)(r.rss>>10));
				}
			kofa_pmem_close(m);
		}
		/*
		 * THP makes the floor 2 MB for a single touched page, so the
		 * bound is generous on purpose: what this rejects is rss
		 * coming back as the whole 64 MB mapping.
		 */
		ok(before > 0 && before < (SIZE / 4),
		   "rss is the touched part, not the mapping");

		/* Now do the destructive thing on purpose. */
		buf = malloc(SIZE);
		m = kofa_pmem_open((uint32_t)kid, 0, &o, &err);
		if (m && buf) {
			kofa_pmem_read(m, base, buf, SIZE);
			kofa_pmem_close(m);
		}
		free(buf);

		m = kofa_pmem_open((uint32_t)kid, 0, &o, &err);
		if (m) {
			while (kofa_pmem_next_region(m, &r))
				if (base >= r.base &&
				    base < r.base + r.size)
					after = r.rss;
			kofa_pmem_close(m);
		}
		ok(after == before,
		   "rss unchanged after the whole mapping was read");
	}

	kill(kid, 9);
	waitpid(kid, NULL, 0);
}

/* An unexamined or unmeasured region must never land in bytes_resident. */
static void test_measured_split(void)
{
	struct kofa_plist *l;
	struct kofa_proc p;
	struct kofa_pmem_option o;
	uint64_t resident = 0, virt = 0;
	int err = 0;

	printf("\nmeasured and assumed stay in different columns:\n");

	memset(&o, 0, sizeof o);
	o.want = KOFA_MW_DEFAULT;
	o.pagemap_min = 1ull << 40;   /* nothing gets a pagemap read */

	l = kofa_plist_open(NULL, &err);
	if (!l)
		return;
	while (kofa_plist_next(l, &p)) {
		struct kofa_pmem *m;
		struct kofa_region r;
		struct kofa_pmem_stat st;

		if (p.flags & (KOFA_PF_REFUSED | KOFA_PF_KERNEL))
			continue;
		m = kofa_pmem_open(p.pid, p.start_time, &o, &err);
		if (!m)
			continue;
		while (kofa_pmem_next_region(m, &r))
			;
		kofa_pmem_stats(m, &st);
		resident += st.bytes_resident;
		virt += st.bytes_virtual;
		kofa_pmem_close(m);
	}
	kofa_plist_close(l);

	/*
	 * smaps still measures rss even with pagemap switched off, so resident
	 * is real - what must never happen is resident EXCEEDING virtual,
	 * which is precisely what the size-standing-in-for-rss bug produced.
	 */
	ok(resident <= virt, "resident never exceeds virtual");
	printf("       resident %.1f MB of %.1f MB virtual\n",
	       resident / 1048576.0, virt / 1048576.0);
}

/*
 * DIRTY_CODE FIRES WHEN CODE IS PATCHED AND AT NO OTHER TIME.
 *
 * The machine-wide baseline is 0 kB of private-dirty across 1079 executable
 * file-backed regions, so the flag is worth exactly as much as its ability to
 * leave zero and come back. The child patches one byte of its own .text, which
 * is what an inline hook is.
 */
static void test_dirty_code(void)
{
	int fd[2];
	pid_t kid;
	unsigned long base = 0;

	printf("\ndirty code page:\n");

	if (pipe(fd))
		return;

	kid = fork();
	if (kid == 0) {
		/* A page of our own text. main() is as good as any. */
		unsigned long pg = (unsigned long)(uintptr_t)&test_dirty_code;

		close(fd[0]);
		pg &= ~4095ul;
		if (mprotect((void *)(uintptr_t)pg, 4096,
			     PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
			/* Write a byte back to itself: the value does not
			 * change, the page becomes private and dirty. */
			volatile unsigned char *b =
				(volatile unsigned char *)(uintptr_t)pg;
			*b = *b;
			base = pg;
		}
		write(fd[1], &base, sizeof base);
		pause();
		_exit(0);
	}
	close(fd[1]);
	read(fd[0], &base, sizeof base);
	usleep(150000);

	if (!base) {
		printf("  skip mprotect refused\n");
	} else {
		struct kofa_pmem *m;
		struct kofa_region r;
		int err = 0, dirty = 0, seen = 0, others = 0;

		m = kofa_pmem_open((uint32_t)kid, 0, NULL, &err);
		if (m) {
			while (kofa_pmem_next_region(m, &r)) {
				if (base >= r.base && base < r.base + r.size) {
					seen = 1;
					dirty = (r.flags &
						 KOFA_RGF_DIRTY_CODE) != 0;
				} else if (r.flags & KOFA_RGF_DIRTY_CODE) {
					others++;
				}
			}
			kofa_pmem_close(m);
		}
		ok(seen, "found the region holding the patched page");
		ok(dirty, "KOFA_RGF_DIRTY_CODE is set on it");
		ok(others == 0, "and on no other region of the process");
	}

	kill(kid, 9);
	waitpid(kid, NULL, 0);
}

int main(void)
{
	test_comm_trap();
	test_dirty_code();
	test_prot_none();
	test_zero_page();
	test_measured_split();

	printf("\n%s (%d failed)\n", fails ? "FAILURES" : "all passed", fails);
	return fails ? 1 : 0;
}
