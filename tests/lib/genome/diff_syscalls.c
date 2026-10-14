/*
 * diff_syscalls - every Linux system call the interpreter answers, by number, for both ABIs.
 *
 * The dispatcher in emu_sys.c is a switch over amd64 numbers behind a translation table for the i386 ones
 * (the two numberings are unrelated: write is 1 and 4). A call the switch does not know is -ENOSYS and is
 * listed once; a call it does know answers something. What a guest cannot see from outside, and a test must say,
 * is WHICH numbers those are, and what each of them answers. Two tables below are that statement, one per ABI:
 * the number, the name, what a call with every argument zero returns (a negative number is -errno, R_EXIT and
 * R_HANDOFF are the two calls that end the run), and in the amd64 table what the call does.
 *
 *   SWEEP    every number from 0 to 511 is made, in a fresh interpreter, with zero arguments. The set the
 *            interpreter answers (the call was not logged as unknown) is EXACTLY the set the table lists:
 *            a handler added without a row, a row whose handler was removed, or a translation that points
 *            at the wrong call fails here
 *   RETURN   each listed call, zero arguments, returns the table's value in the guest's own width (a 32 bit
 *            guest reads -errno in 32 bits), or ends the run with the stop it names
 *   PEER     each i386 row names the amd64 call it is served by; the row's number and name are the i386 ones
 *            (mmap2 is 192, getuid32 is 199) and the peer is the call whose semantics it has
 *
 * The i386 numbers 21, 22 and 25 (mount, umount, stime) used to be translated to access, pipe and getpid, so a
 * guest that mounted a file system was told it worked; they are unknown now, as the sweep checks.
 * Nothing here writes a file.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <phenotype/emu.h>

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

static const uint8_t SELF[] = "SELF-FILE-0123456789abcdefghijklmnopqrstuvwxyz-0123456789-end";

#define CODE   0x400000ull
#define DATA   0x600000ull
#define STACK  0x7ff00000ull


static struct kgenome_emu *mk(unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = bits;
	cfg.max_insn = 1000000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	kgenome_emu_map(e, CODE, NULL, 0, 0x2000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, STACK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_self(e, SELF, sizeof SELF - 1u);
	return e;
}

struct res {
	uint64_t              ret;
	enum kgenome_emu_stop stop;
	int                   done;
};

/* one syscall: nr and up to six arguments */
static struct res sys(struct kgenome_emu *e, unsigned bits, uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
		      uint64_t a3, uint64_t a4, uint64_t a5)
{
	struct res r;
	uint8_t c[128];
	unsigned n = 0;

	memset(&r, 0, sizeof r);
	if (bits == 32) {
		static const uint8_t mv[6] = { 0xbb, 0xb9, 0xba, 0xbe, 0xbf, 0xbd };      /* ebx ecx edx esi edi ebp */
		uint64_t a[6] = { a0, a1, a2, a3, a4, a5 };
		unsigned k;

		for (k = 0; k < 6; k++) {
			uint32_t v = (uint32_t)a[k];

			c[n++] = mv[k];
			memcpy(c + n, &v, 4);
			n += 4;
		}
		c[n++] = 0xb8;
		{
			uint32_t v = (uint32_t)nr;

			memcpy(c + n, &v, 4);
			n += 4;
		}
		c[n++] = 0xcd; c[n++] = 0x80;
	} else {
		static const uint8_t mv[6][2] = { { 0x48, 0xbf }, { 0x48, 0xbe }, { 0x48, 0xba }, { 0x49, 0xba },
						  { 0x49, 0xb8 }, { 0x49, 0xb9 } };    /* rdi rsi rdx r10 r8 r9 */
		uint64_t a[6] = { a0, a1, a2, a3, a4, a5 };
		unsigned k;

		for (k = 0; k < 6; k++) {
			c[n++] = mv[k][0];
			c[n++] = mv[k][1];
			memcpy(c + n, &a[k], 8);
			n += 8;
		}
		c[n++] = 0x48; c[n++] = 0xb8;
		memcpy(c + n, &nr, 8);
		n += 8;
		c[n++] = 0x0f; c[n++] = 0x05;
	}
	c[n++] = 0xf4;
	kgenome_emu_write(e, CODE, c, n);
	kgenome_emu_set_rip(e, CODE);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK + 0x8000);
	r.stop = kgenome_emu_run(e);
	r.done = kgenome_emu_get_rip(e) == CODE + n - 1u;
	r.ret = kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
	if (bits == 32)
		r.ret &= 0xffffffffull;
	return r;
}


#define R_EXIT    INT64_MIN
#define R_HANDOFF (INT64_MIN + 1)

struct row {
	int         nr;
	const char *name;
	int64_t     ret0;
	int         peer;       /* i386: the amd64 number whose semantics it has */
	const char *what;
};

static const struct row SYS64[] = {
	{ 0, "read", 0, 0, "descriptor 0 is standard input at end of file; the descriptor open() returned serves the scanned file from its position" },
	{ 1, "write", 0, 0, "the count is returned; what goes to descriptors 1 and 2 is kept in a bounded buffer for the report" },
	{ 2, "open", 3, 0, "every path opens: the one descriptor, 3, which is the scanned file" },
	{ 3, "close", 0, 0, "0" },
	{ 4, "stat", -14, 0, "writes the struct stat of the scanned file (st_size at the ABI offset); -EFAULT for an unmapped buffer" },
	{ 5, "fstat", -14, 0, "as stat, for a descriptor" },
	{ 6, "lstat", -14, 0, "as stat" },
	{ 7, "poll", 0, 0, "0: nothing is ready" },
	{ 8, "lseek", 0, 0, "sets and returns the position in the scanned file" },
	{ 9, "mmap", -12, 0, "anonymous: fresh zero pages (below 4 GiB for a 32 bit guest); a descriptor-backed map is a window onto the scanned file; PROT_NONE only reserves; length 0 is -ENOMEM" },
	{ 10, "mprotect", 0, 0, "0: memory is not given back or restricted" },
	{ 11, "munmap", 0, 0, "0: memory is not given back" },
	{ 12, "brk", 0, 0, "0: the interpreter keeps no program break" },
	{ 13, "rt_sigaction", 0, 0, "0: accepted, the old action is zero" },
	{ 14, "rt_sigprocmask", 0, 0, "0: accepted" },
	{ 16, "ioctl", -25, 0, "-ENOTTY: no descriptor is a terminal" },
	{ 17, "pread64", 0, 0, "reads the scanned file at an offset without moving the position" },
	{ 18, "pwrite64", 0, 0, "0: nothing is written" },
	{ 19, "readv", 0, 0, "scatter read from the scanned file into each buffer of the vector, in order (the vector is two words per entry)" },
	{ 20, "writev", 0, 0, "the lengths of the vector are added and returned; an unreadable vector writes nothing" },
	{ 21, "access", 0, 0, "0: every path exists" },
	{ 22, "pipe", -14, 0, "-EFAULT for an unmapped buffer" },
	{ 23, "select", 0, 0, "0: nothing is ready" },
	{ 24, "sched_yield", 0, 0, "0" },
	{ 25, "mremap", -22, 0, "grows by moving with MAYMOVE, shrinks in place, -ENOMEM when growing without it, -EINVAL for length 0" },
	{ 28, "madvise", 0, 0, "0" },
	{ 32, "dup", 3, 0, "the one descriptor, 3" },
	{ 33, "dup2", 0, 0, "0" },
	{ 34, "pause", 0, 0, "returns at once, 0" },
	{ 35, "nanosleep", 0, 0, "granted in full: the clock advances, nothing waits, the remainder is zero" },
	{ 37, "alarm", 0, 0, "0: no alarm was pending" },
	{ 38, "setitimer", 0, 0, "0" },
	{ 39, "getpid", 1, 0, "a fixed pid, 1" },
	{ 56, "clone", 1, 0, "a thread id that increases; no thread ever runs" },
	{ 59, "execve", R_HANDOFF, 0, "hands over to the new image: stop HANDOFF" },
	{ 60, "exit", R_EXIT, 0, "ends the run: stop EXIT" },
	{ 62, "kill", -1, 0, "-EPERM: a stub does not get to end itself that way" },
	{ 63, "uname", -14, 0, "writes six 65 byte names (a Debian x86_64 host); -EFAULT for an unmapped buffer" },
	{ 72, "fcntl", 3, 0, "the one descriptor for F_DUPFD, 0 for the rest" },
	{ 77, "ftruncate", 0, 0, "0" },
	{ 79, "getcwd", -34, 0, "the invented working directory; -ERANGE when the buffer is too small" },
	{ 89, "readlink", 0, 0, "/proc/self/exe, truncated to the buffer; the length is returned" },
	{ 96, "gettimeofday", 0, 0, "a clock that only moves forward; 0" },
	{ 97, "getrlimit", 0, 0, "0: fills the limits" },
	{ 99, "sysinfo", -14, 0, "RAM and uptime of an ordinary machine; -EFAULT for an unmapped buffer" },
	{ 100, "times", 0, 0, "the same forward clock, in ticks" },
	{ 101, "ptrace", 0, 0, "0: PTRACE_TRACEME succeeds" },
	{ 102, "getuid", 1000, 0, "1000: an ordinary user, not root" },
	{ 104, "getgid", 1000, 0, "1000" },
	{ 107, "geteuid", 1000, 0, "1000" },
	{ 108, "getegid", 1000, 0, "1000" },
	{ 110, "getppid", 1, 0, "1" },
	{ 131, "sigaltstack", 0, 0, "0" },
	{ 135, "personality", 0, 0, "0" },
	{ 137, "statfs", -14, 0, "ext4 (0xEF53), 100 GB, half free - not overlayfs and not tmpfs; the buffer is the SECOND argument in both ABIs; -EFAULT for an unmapped buffer" },
	{ 138, "fstatfs", -14, 0, "as statfs, for a descriptor" },
	{ 157, "prctl", 0, 0, "0" },
	{ 158, "arch_prctl", -22, 0, "sets the FS and GS base; -EINVAL for a code it does not know" },
	{ 160, "setrlimit", 0, 0, "0" },
	{ 186, "gettid", 1, 0, "a fixed tid, 1" },
	{ 201, "time", 0, 0, "the forward clock in seconds; stored through the pointer when given" },
	{ 202, "futex", 0, 0, "0; a wait nobody wakes is stalled after a while" },
	{ 204, "sched_getaffinity", -22, 0, "one CPU; -EINVAL when the size cannot hold the mask" },
	{ 218, "set_tid_address", 1, 0, "the tid" },
	{ 222, "timer_create", 0, 0, "0" },
	{ 223, "timer_settime", 0, 0, "0" },
	{ 228, "clock_gettime", -14, 0, "the forward clock; -EFAULT for an unmapped timespec" },
	{ 229, "clock_getres", 0, 0, "0: a resolution of one nanosecond" },
	{ 230, "clock_nanosleep", 0, 0, "as nanosleep" },
	{ 231, "exit_group", R_EXIT, 0, "ends the run: stop EXIT" },
	{ 234, "tgkill", 0, 0, "0" },
	{ 257, "openat", 3, 0, "as open" },
	{ 262, "newfstatat", -14, 0, "as stat" },
	{ 267, "readlinkat", 0, 0, "as readlink" },
	{ 269, "faccessat", 0, 0, "as access" },
	{ 273, "set_robust_list", 0, 0, "0" },
	{ 292, "dup3", 0, 0, "0" },
	{ 293, "pipe2", -14, 0, "as pipe" },
	{ 302, "prlimit64", 0, 0, "0" },
	{ 309, "getcpu", 0, 0, "0: CPU 0, node 0" },
	{ 318, "getrandom", 0, 0, "fills the buffer with deterministic bytes, bounded; -EFAULT for an unmapped buffer; the length" },
	{ 319, "memfd_create", 3, 0, "the one descriptor, 3" },
	{ 334, "rseq", 0, 0, "0" },
	{ 439, "faccessat2", 0, 0, "as access" },
};

static const struct row SYS32[] = {
	{ 1, "exit", R_EXIT, 60, "as exit on amd64" },
	{ 2, "fork", 1, 39, "as getpid on amd64" },
	{ 3, "read", 0, 0, "as read on amd64" },
	{ 4, "write", 0, 1, "as write on amd64" },
	{ 5, "open", 3, 2, "as open on amd64" },
	{ 6, "close", 0, 3, "as close on amd64" },
	{ 11, "execve", R_HANDOFF, 59, "as execve on amd64" },
	{ 13, "time", 0, 201, "as time on amd64" },
	{ 19, "lseek", 0, 8, "as lseek on amd64" },
	{ 20, "getpid", 1, 39, "as getpid on amd64" },
	{ 26, "ptrace", 0, 101, "as ptrace on amd64" },
	{ 33, "access", 0, 21, "as access on amd64" },
	{ 41, "dup", 3, 32, "as dup on amd64" },
	{ 42, "pipe", -14, 22, "as pipe on amd64" },
	{ 43, "times", 0, 100, "as times on amd64" },
	{ 45, "brk", 0, 12, "as brk on amd64" },
	{ 54, "ioctl", -25, 16, "as ioctl on amd64" },
	{ 55, "fcntl", 3, 72, "as fcntl on amd64" },
	{ 63, "dup2", 0, 33, "as dup2 on amd64" },
	{ 64, "getppid", 1, 110, "as getppid on amd64" },
	{ 75, "setrlimit", 0, 160, "as setrlimit on amd64" },
	{ 76, "getrlimit", 0, 97, "as getrlimit on amd64" },
	{ 78, "gettimeofday", 0, 96, "as gettimeofday on amd64" },
	{ 85, "readlink", 0, 89, "as readlink on amd64" },
	{ 90, "old_mmap", -12, 9, "as mmap on amd64" },
	{ 91, "munmap", 0, 11, "as munmap on amd64" },
	{ 93, "ftruncate", 0, 77, "as ftruncate on amd64" },
	{ 99, "statfs", -14, 137, "as statfs on amd64" },
	{ 100, "fstatfs", -14, 138, "as fstatfs on amd64" },
	{ 116, "sysinfo", -14, 99, "as sysinfo on amd64" },
	{ 120, "clone", 1, 56, "as clone on amd64" },
	{ 122, "uname", -14, 63, "as uname on amd64" },
	{ 125, "mprotect", 0, 10, "as mprotect on amd64" },
	{ 136, "personality", 0, 135, "as personality on amd64" },
	{ 145, "readv", 0, 19, "as readv on amd64" },
	{ 146, "writev", 0, 20, "as writev on amd64" },
	{ 158, "sched_yield", 0, 24, "as sched_yield on amd64" },
	{ 162, "nanosleep", 0, 35, "as nanosleep on amd64" },
	{ 163, "mremap", -22, 25, "as mremap on amd64" },
	{ 172, "prctl", 0, 157, "as prctl on amd64" },
	{ 174, "rt_sigaction", 0, 13, "as rt_sigaction on amd64" },
	{ 175, "rt_sigprocmask", 0, 14, "as rt_sigprocmask on amd64" },
	{ 180, "pread64", 0, 17, "as pread64 on amd64" },
	{ 181, "pwrite64", 0, 18, "as pwrite64 on amd64" },
	{ 183, "getcwd", -34, 79, "as getcwd on amd64" },
	{ 191, "ugetrlimit", 0, 97, "as getrlimit on amd64" },
	{ 192, "mmap2", -12, 9, "as mmap on amd64" },
	{ 197, "fstat64", -14, 5, "as fstat on amd64" },
	{ 199, "getuid32", 1000, 102, "as getuid on amd64" },
	{ 200, "getgid32", 1000, 104, "as getgid on amd64" },
	{ 201, "geteuid32", 1000, 107, "as geteuid on amd64" },
	{ 202, "getegid32", 1000, 108, "as getegid on amd64" },
	{ 219, "madvise", 0, 28, "as madvise on amd64" },
	{ 221, "fcntl64", 3, 72, "as fcntl on amd64" },
	{ 224, "gettid", 1, 186, "as gettid on amd64" },
	{ 240, "futex", 0, 202, "as futex on amd64" },
	{ 242, "sched_getaffinity", -22, 204, "as sched_getaffinity on amd64" },
	{ 252, "exit_group", R_EXIT, 231, "as exit_group on amd64" },
	{ 265, "clock_gettime", -14, 228, "as clock_gettime on amd64" },
	{ 266, "clock_getres", 0, 229, "as clock_getres on amd64" },
	{ 267, "clock_nanosleep", 0, 230, "as clock_nanosleep on amd64" },
	{ 270, "tgkill", 0, 234, "as tgkill on amd64" },
	{ 295, "openat", 3, 257, "as openat on amd64" },
	{ 305, "readlinkat", 0, 267, "as readlinkat on amd64" },
	{ 307, "faccessat", 0, 269, "as faccessat on amd64" },
	{ 330, "dup3", 0, 292, "as dup3 on amd64" },
	{ 331, "pipe2", -14, 293, "as pipe2 on amd64" },
	{ 355, "getrandom", 0, 318, "as getrandom on amd64" },
	{ 356, "memfd_create", 3, 319, "as memfd_create on amd64" },
	{ 439, "faccessat2", 0, 439, "as faccessat2 on amd64" },
};

#define N64 (sizeof SYS64 / sizeof SYS64[0])
#define N32 (sizeof SYS32 / sizeof SYS32[0])

static const struct row *row_of(unsigned bits, unsigned nr)
{
	const struct row *t = bits == 32 ? SYS32 : SYS64;
	unsigned i, n = bits == 32 ? (unsigned)N32 : (unsigned)N64;

	for (i = 0; i < n; i++)
		if ((unsigned)t[i].nr == nr)
			return &t[i];
	return NULL;
}

static void t_sweep(unsigned bits)
{
	unsigned nr, handled = 0;

	for (nr = 0; nr < 512; nr++) {
		struct kgenome_emu *e = mk(bits);
		uint32_t unk[8];
		unsigned nu;
		const struct row *r = row_of(bits, nr);

		if (!e) {
			CK(0, "emulator");
			return;
		}
		(void)sys(e, bits, nr, 0, 0, 0, 0, 0, 0);
		nu = kgenome_emu_unknown_syscalls(e, unk, 8);
		if (!nu)
			handled++;
		CK((nu == 0) == (r != NULL), "%u bit number %u: %s", bits, nr,
		   r ? "the table lists it and the interpreter logs it as unknown" : "the interpreter answers it and the table does not list it");
		kgenome_emu_free(e);
	}
	CK(handled == (bits == 32 ? N32 : N64), "%u bit: %u number(s) answered, %zu listed", bits, handled, bits == 32 ? N32 : N64);
}

static void t_returns(unsigned bits)
{
	const struct row *t = bits == 32 ? SYS32 : SYS64;
	unsigned i, n = bits == 32 ? (unsigned)N32 : (unsigned)N64;

	for (i = 0; i < n; i++) {
		struct kgenome_emu *e = mk(bits);
		struct res r;
		uint64_t want;

		if (!e) {
			CK(0, "emulator");
			return;
		}
		r = sys(e, bits, (uint64_t)t[i].nr, 0, 0, 0, 0, 0, 0);
		if (t[i].ret0 == R_EXIT) {
			CK(r.stop == KGENOME_EMU_STOP_EXIT && !r.done, "%u bit %s(%d): ends the run (%s)", bits, t[i].name, t[i].nr,
			   kgenome_emu_stop_name(r.stop));
		} else if (t[i].ret0 == R_HANDOFF) {
			CK(r.stop == KGENOME_EMU_STOP_HANDOFF && !r.done, "%u bit %s(%d): hands over (%s)", bits, t[i].name, t[i].nr,
			   kgenome_emu_stop_name(r.stop));
		} else {
			want = bits == 32 ? (uint64_t)(uint32_t)(int32_t)t[i].ret0 : (uint64_t)t[i].ret0;
			CK(r.done && r.ret == want, "%u bit %s(%d) with zero arguments returns %lld (got %llx, done %d)", bits, t[i].name, t[i].nr,
			   (long long)t[i].ret0, (unsigned long long)r.ret, r.done);
		}
		kgenome_emu_free(e);
	}
}

/* an i386 row is served by the amd64 call it names: the same zero-argument answer, in 32 bits, except where the
 * ABI itself differs (which is the point of diff_abi.c) */
static void t_peers(void)
{
	unsigned i;

	for (i = 0; i < N32; i++) {
		const struct row *p = row_of(64, (unsigned)SYS32[i].peer);

		CK(p != NULL, "i386 %s(%d): its peer, amd64 %d, is a call the interpreter answers", SYS32[i].name, SYS32[i].nr, SYS32[i].peer);
		if (p)
			CK(SYS32[i].ret0 == p->ret0 || (SYS32[i].ret0 == (int32_t)p->ret0), "i386 %s(%d) answers what amd64 %s(%d) does (%lld vs %lld)",
			   SYS32[i].name, SYS32[i].nr, p->name, p->nr, (long long)SYS32[i].ret0, (long long)p->ret0);
	}
}

int main(void)
{
	t_sweep(64);
	t_sweep(32);
	t_returns(64);
	t_returns(32);
	t_peers();
	printf("diff_syscalls: %zu amd64 and %zu i386 call(s) listed, 512 numbers swept in each ABI\n", N64, N32);
	if (fails) {
		printf("diff_syscalls: FAILED (%d)\n", fails);
		return 1;
	}
	printf("diff_syscalls: ok\n");
	return 0;
}
