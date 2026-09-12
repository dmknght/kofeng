/*
 * antarc_walk - guard the four things that actually broke in the /proc walk.
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
#include <sys/socket.h>
#include <fcntl.h>
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
	       (double)resident / 1048576.0, (double)virt / 1048576.0);
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

/*
 * Find a process by pid in a fresh plist walk. Returns 1 and fills *out.
 * Strings in *out point into the list, so it stays open until the caller is
 * done - hence the handle coming back rather than being closed here.
 */
static int find_proc(struct kofa_plist *l, pid_t pid, struct kofa_proc *out)
{
	while (kofa_plist_next(l, out))
		if (out->pid == (uint32_t)pid)
			return 1;
	return 0;
}

/*
 * THE REVERSE SHELL, AND THE THING THAT IS NOT ONE.
 *
 * Two children with socket stdio, differing in one respect: the first has ONE
 * socket duplicated onto stdin and stdout, which is what `>&` produces and what
 * a reverse shell is; the second has the two ends of a socketpair, which is
 * what every spawned language server on this desktop has. Eight of those were
 * false positives before the same-socket test existed, and this is the case
 * that keeps them out.
 */
static void test_reverse_shell_shape(void)
{
	int sp[2], sp2[2];
	pid_t dup_kid, pair_kid;

	printf("\nreverse shell shape (same socket vs socketpair):\n");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		return;
	dup_kid = fork();
	if (dup_kid == 0) {
		int f;

		/*
		 * ONE socket on all three - what `>&` produces. All three,
		 * and every inherited descriptor closed, because that is the
		 * shape being modelled: a fork+exec that leaves the test's own
		 * descriptors open produces a child holding things no reverse
		 * shell holds, and then STDIO_ONLY is correctly off and the
		 * test is wrong rather than the library.
		 */
		dup2(sp[1], 0);
		dup2(sp[1], 1);
		dup2(sp[1], 2);
		for (f = 3; f < 64; f++)
			close(f);
		execl("/bin/sh", "sh", "-c", "read x", (char *)NULL);
		_exit(1);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp2)) {
		kill(dup_kid, 9);
		return;
	}
	pair_kid = fork();
	if (pair_kid == 0) {
		int f;

		/* TWO sockets, one per direction - an ordinary spawned
		 * child. */
		dup2(sp2[0], 0);
		dup2(sp2[1], 1);
		for (f = 3; f < 64; f++)
			close(f);
		execl("/bin/sh", "sh", "-c", "read x", (char *)NULL);
		_exit(1);
	}
	usleep(250000);

	{
		struct kofa_plist *l;
		struct kofa_proc p;
		int err = 0;

		l = kofa_plist_open(NULL, &err);
		if (l && find_proc(l, dup_kid, &p)) {
			ok(!strncmp(p.fd_stdin, "socket:", 7) &&
			   !strcmp(p.fd_stdin, p.fd_stdout),
			   "fd 0 and fd 1 name one socket");
			ok(p.fds_read && p.n_fd && p.n_like_stdin == p.n_fd,
			   "every descriptor names that same object");
		} else {
			ok(0, "found the dup'd-socket child");
		}
		kofa_plist_close(l);

		l = kofa_plist_open(NULL, &err);
		if (l && find_proc(l, pair_kid, &p)) {
			ok(!strncmp(p.fd_stdin, "socket:", 7),
			   "a socketpair child still has socket stdio");
			ok(strcmp(p.fd_stdin, p.fd_stdout) != 0,
			   "but the two ends differ - the eight false "
			   "positives");
		} else {
			ok(0, "found the socketpair child");
		}
		kofa_plist_close(l);
	}

	kill(dup_kid, 9); kill(pair_kid, 9);
	waitpid(dup_kid, NULL, 0); waitpid(pair_kid, NULL, 0);
	close(sp[0]); close(sp[1]); close(sp2[0]); close(sp2[1]);
}

/*
 * STDIO_ONLY IS ABOUT HOLDING NOTHING ELSE, AND THIS IS THE CASE THAT SAYS SO.
 *
 * A child with the same socket on stdin and stdout - so SAME_SOCKET fires -
 * but also holding one ordinary file open. A relay like netcat or socat is
 * this shape and more: it keeps its listening socket as well as the accepted
 * one. The flag has to stay off, or "it has only its stdio" means nothing.
 */
static void test_stdio_only_negative(void)
{
	int sp[2];
	pid_t kid;

	printf("\nSTDIO_ONLY is off when anything else is held:\n");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		return;
	kid = fork();
	if (kid == 0) {
		int f;

		dup2(sp[1], 0);
		dup2(sp[1], 1);
		dup2(sp[1], 2);
		for (f = 3; f < 64; f++)
			close(f);
		/* One extra descriptor on something that is not the socket -
		 * which is the least a relay holds. */
		if (open("/dev/null", O_RDONLY) < 0)
			_exit(1);
		execl("/bin/sh", "sh", "-c", "read x", (char *)NULL);
		_exit(1);
	}
	usleep(250000);

	{
		struct kofa_plist *l;
		struct kofa_proc p;
		int err = 0;

		l = kofa_plist_open(NULL, &err);
		if (l && find_proc(l, kid, &p)) {
			ok(!strcmp(p.fd_stdin, p.fd_stdout),
			   "fd 0 and fd 1 still name one object");
			ok(p.fds_read && p.n_like_stdin < p.n_fd,
			   "but not every descriptor does - it holds a file "
			   "too");
		} else {
			ok(0, "found the child");
		}
		kofa_plist_close(l);
	}

	kill(kid, 9);
	waitpid(kid, NULL, 0);
	close(sp[0]); close(sp[1]);
}

/* A userland process wearing a kernel thread's name. */
static void test_fake_kthread(void)
{
	int fd[2];
	pid_t kid;
	unsigned long go = 0;

	printf("\nkernel thread masquerade:\n");

	if (pipe(fd))
		return;
	kid = fork();
	if (kid == 0) {
		close(fd[0]);
		prctl(PR_SET_NAME, "[kworker/0:9]", 0, 0, 0);
		write(fd[1], &go, sizeof go);
		pause();
		_exit(0);
	}
	close(fd[1]);
	read(fd[0], &go, sizeof go);
	usleep(150000);

	{
		struct kofa_plist *l;
		struct kofa_proc p;
		int err = 0;

		l = kofa_plist_open(NULL, &err);
		if (l && find_proc(l, kid, &p)) {
			ok(p.comm[0] == '[' &&
			   p.comm[strlen(p.comm) - 1] == ']',
			   "the name it chose looks like a kernel thread's");
			ok(!p.is_kthread,
			   "and the kernel's own bit says it is not one");
			ok(p.exe_on_disk,
			   "while an executable of its own resolves on disk");
		} else {
			ok(0, "found the masquerading child");
		}
		kofa_plist_close(l);
	}

	kill(kid, 9);
	waitpid(kid, NULL, 0);
}

/*
 * THE CHUNK WALK, over a layout this test decided.
 *
 * The child maps a region and writes a known pattern into it with holes:
 *
 *      page 0   content "AAAA..."
 *      page 1   untouched            <- zero
 *      page 2   untouched            <- zero
 *      page 3   content "BBBB..."
 *      page 4   content "CCCC..."
 *      page 5   untouched            <- zero
 *
 * What must come back is two chunks - page 0, and pages 3-4 together - at the
 * addresses those pages actually have. Getting the ADDRESS wrong is the
 * failure this test exists for: a chunk whose bytes are right and whose
 * address is off by a page sends every finding to the wrong place, and nothing
 * about the bytes would show it.
 */
static void test_chunk_walk(void)
{
	int fd[2];
	pid_t kid;
	unsigned long base = 0;
	const size_t PG = 4096, NPG = 6;

	printf("\nchunk walk skips zero pages and keeps addresses:\n");

	if (pipe(fd))
		return;
	kid = fork();
	if (kid == 0) {
		char *m = mmap(NULL, NPG * PG, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		close(fd[0]);
		if (m == MAP_FAILED)
			_exit(1);
		memset(m + 0 * PG, 'A', PG);
		memset(m + 3 * PG, 'B', PG);
		memset(m + 4 * PG, 'C', PG);
		/*
		 * READ pages 1, 2 and 5 without writing them. That is what
		 * makes them PRESENT AND ZERO - a read fault on untouched
		 * anonymous memory maps the shared zero page - and it is the
		 * only state in which the zero filter has anything to do.
		 * Untouched pages never reach it, because pagemap already
		 * leaves them out.
		 */
		{
			volatile unsigned char sink = 0;

			sink = (unsigned char)(sink + m[1 * PG]);
			sink = (unsigned char)(sink + m[2 * PG]);
			sink = (unsigned char)(sink + m[5 * PG]);
			(void)sink;
		}
		base = (unsigned long)(uintptr_t)m;
		if (write(fd[1], &base, sizeof base) != sizeof base)
			_exit(1);
		pause();
		_exit(0);
	}
	close(fd[1]);
	if (read(fd[0], &base, sizeof base) != (ssize_t)sizeof base)
		return;
	usleep(150000);

	{
		struct kofa_pmem_option o;
		struct kofa_pmem *m;
		struct kofa_region r;
		struct kofa_chunk c;
		struct kofa_pmem_stat st;
		int err = 0, found = 0, n = 0;
		uint64_t seen_a = 0, seen_bc = 0;

		memset(&o, 0, sizeof o);
		o.want = KOFA_MW_DEFAULT | KOFA_MW_HEAP;
		o.max_heap_region = NPG * PG;
		o.pagemap_min = 0;          /* always consult it here */

		m = kofa_pmem_open((uint32_t)kid, 0, &o, &err);
		if (m) {
			while (kofa_pmem_next_region(m, &r)) {
				if (base < r.base || base >= r.base + r.size)
					continue;
				found = 1;
				while (kofa_pmem_next_chunk(m, &r, &c)) {
					const unsigned char *p = c.p;

					n++;
					if (p[0] == 'A')
						seen_a = c.addr;
					else if (p[0] == 'B')
						seen_bc = c.addr;
					/* Nothing handed over may be a zero
					 * page - that is the whole filter. */
					if (c.len >= 4096 && !p[0] &&
					    !p[4095])
						fails++;
				}
				break;
			}
			kofa_pmem_stats(m, &st);
			kofa_pmem_close(m);
		}

		ok(found, "found the mapping");
		ok(n == 2, "two chunks: the lone page, and the adjacent pair");
		ok(seen_a == base, "the first chunk is at the mapping base");
		ok(seen_bc == base + 3 * PG,
		   "the second starts at page 3, not where the read did");
		ok(st.bytes_zero > 0, "zero pages were counted, not just cut");
		printf("       %d chunk(s), %llu B read, %llu B of it zero\n",
		       n, (unsigned long long)st.bytes_read,
		       (unsigned long long)st.bytes_zero);
	}

	kill(kid, 9);
	waitpid(kid, NULL, 0);
}

/*
 * ONE MAPPED OBJECT IS ONE GROUP, however many VMAs the loader split it into.
 *
 * Linux has no AllocationBase - see the top of aproc.h - so this library
 * groups by adjacency and backing inode, and that guess is the only thing
 * standing between a caller and reporting one shared object three times. A
 * loaded .so is r--p for its headers, r-xp for its text and rw-p for its data,
 * all adjacent and all the same inode; they must share a group_id, and the
 * next object along must not.
 *
 * Measured over this process's own address space rather than a synthetic one:
 * the layout being tested is the loader's, and a made-up one would be testing
 * the test.
 */
static void test_grouping(void)
{
	struct kofa_pmem_option o;
	struct kofa_pmem *m;
	struct kofa_region r;
	int err = 0;
	uint64_t prev_group = 0, prev_inode = 0, prev_end = 0;
	int have_prev = 0, multi = 0, split_groups = 0, checked = 0;

	printf("\nthe VMAs of one mapped object share a group:\n");

	memset(&o, 0, sizeof o);
	o.want = KOFA_MW_PAGEMAP;      /* every region, not just executable */

	m = kofa_pmem_open((uint32_t)getpid(), 0, &o, &err);
	if (!m) {
		ok(0, "opened our own process");
		return;
	}

	while (kofa_pmem_next_region(m, &r)) {
		if (have_prev && r.inode && r.inode == prev_inode &&
		    r.base == prev_end) {
			/* Adjacent, same file: the loader's own split. */
			checked++;
			if (r.group_id == prev_group)
				multi++;
			else
				split_groups++;
		}
		prev_group = r.group_id;
		prev_inode = r.inode;
		prev_end   = r.base + r.size;
		have_prev  = 1;
	}
	kofa_pmem_close(m);

	ok(checked > 0, "the loader did split at least one object for us");
	ok(split_groups == 0,
	   "no adjacent same-inode pair landed in different groups");
	printf("       %d adjacent same-file pair(s), %d grouped, %d split\n",
	       checked, multi, split_groups);
}

/*
 * THE SWEEP BUDGET STOPS THE WALK AND SAYS SO.
 *
 * A budget that merely stopped would be the failure this tree treats as worse
 * than an error: a caller told it examined everything over a set it abandoned.
 */
static void test_sweep_budget(void)
{
	struct kofa_sweep sw;
	struct kofa_pmem_option o;
	struct kofa_plist *l;
	struct kofa_proc p;
	int err = 0;
	uint64_t read_total = 0;

	printf("\na sweep budget bounds the walk and reports the refusal:\n");

	memset(&sw, 0, sizeof sw);
	sw.max_bytes = 64u * 1024u;      /* deliberately tiny */

	memset(&o, 0, sizeof o);
	o.want = KOFA_MW_DEFAULT | KOFA_MW_EXEC_ONLY;
	o.sweep = &sw;

	l = kofa_plist_open(NULL, &err);
	if (!l)
		return;
	while (kofa_plist_next(l, &p)) {
		struct kofa_pmem *m;
		struct kofa_region r;
		struct kofa_chunk c;
		struct kofa_pmem_stat st;

		if (p.flags & (KOFA_PF_REFUSED | KOFA_PF_KERNEL))
			continue;
		m = kofa_pmem_open(p.pid, p.start_time, &o, &err);
		if (!m)
			continue;
		while (kofa_pmem_next_region(m, &r))
			while (kofa_pmem_next_chunk(m, &r, &c))
				;
		kofa_pmem_stats(m, &st);
		read_total += st.bytes_read;
		kofa_pmem_close(m);
	}
	kofa_plist_close(l);

	ok(sw.used <= sw.max_bytes, "the walk stayed inside the budget");
	ok(read_total == sw.used, "and the shared counter agrees with the walk");
	ok(sw.regions_refused > 0 || sw.refused > 0,
	   "running out was reported, not silent");
	printf("       used %llu of %llu B, %u region(s) refused\n",
	       (unsigned long long)sw.used,
	       (unsigned long long)sw.max_bytes, sw.regions_refused);
}

int main(void)
{
	test_comm_trap();
	test_chunk_walk();
	test_grouping();
	test_sweep_budget();
	test_reverse_shell_shape();
	test_stdio_only_negative();
	test_fake_kthread();
	test_dirty_code();
	test_prot_none();
	test_zero_page();
	test_measured_split();

	printf("\n%s (%d failed)\n", fails ? "FAILURES" : "all passed", fails);
	return fails ? 1 : 0;
}
