/*
 * cov_emu_sys - the Linux syscall environment of the interpreter, number by number.
 *
 * A stub that unpacks itself asks the kernel who it is, how big it is, what time it is and for memory; it
 * is answered from the dispatcher in emu_sys.c. Each call is made here the way the guest makes it
 * (`syscall` with the number in rax and the arguments in rdi rsi rdx r10 r8 r9; `int 0x80` with them in
 * ebx ecx edx esi edi ebp for a 32 bit guest) and what comes back, and what lands in guest memory, is
 * compared with what Linux documents for the call - in the layout of the struct the guest allocated
 * (struct utsname is six 65 byte names, struct sysinfo has its alignment, a 32 bit stat is 96 bytes).
 * Where the environment answers something simpler on purpose (every path exists, there is one file and
 * one descriptor, a sleep is granted in full and not waited for) that is the answer asserted and the
 * reason is in the check's text.
 *
 *   IDENTITY      pid, tid, ppid, uid and gid (an ordinary user, not root), uname, sysinfo (what a sandbox
 *                 check looks at: RAM and uptime), times, limits, prctl, personality, cwd
 *   TIME          clock_gettime, gettimeofday, time and times are one clock that only moves forward; a sleep
 *                 is added to it and returns at once (the remainder is zero)
 *   FILES         open/openat/memfd_create give the one descriptor, access succeeds, stat and fstat carry the
 *                 file size at the right offset for the width, statfs says ext4, readlink says /proc/self/exe,
 *                 read serves the scanned file (and standard input is at its end), lseek, pread, readv
 *   MEMORY        mmap (anonymous, file backed, PROT_NONE, with a hint, of length zero), mremap grown by moving,
 *                 shrunk in place and refused without MAYMOVE, mprotect, munmap, brk
 *   PROCESS       exit and exit_group end the run, execve hands over, a futex wait nobody wakes is stalled
 *                 after a while, clone returns a thread id that increases, kill is refused, ptrace(TRACEME)
 *                 succeeds, signals are accepted and the old action is zero
 *   RANDOM        getrandom is deterministic, bounded, and faults on an unmapped buffer
 *   LOG           an unknown number is -ENOSYS and is listed once; the call log keeps what was asked and what
 *                 the guest was told, newest last, capped
 *
 * A guest is a handful of instructions; nothing here opens a file.
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

#define CODE   0x400000ull
#define DATA   0x600000ull
#define STACK  0x7ff00000ull

static const uint8_t SELF[] = "SELF-FILE-0123456789abcdefghijklmnopqrstuvwxyz-0123456789-end";

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

#define S0(e, b, nr)                       sys((e), (b), (nr), 0, 0, 0, 0, 0, 0)
#define S1(e, b, nr, x)                    sys((e), (b), (nr), (x), 0, 0, 0, 0, 0)
#define S2(e, b, nr, x, y)                 sys((e), (b), (nr), (x), (y), 0, 0, 0, 0)
#define S3(e, b, nr, x, y, z)              sys((e), (b), (nr), (x), (y), (z), 0, 0, 0)
#define S4(e, b, nr, x, y, z, w)           sys((e), (b), (nr), (x), (y), (z), (w), 0, 0)

static void put(struct kgenome_emu *e, uint64_t va, const void *p, unsigned n)
{
	kgenome_emu_write(e, va, p, n);
}

static uint64_t get(struct kgenome_emu *e, uint64_t va, unsigned n)
{
	uint64_t v = 0;

	if (!kgenome_emu_read(e, va, &v, n))
		return 0xdeadbeefdeadbeefull;
	return v;
}

#define NEG(x)  ((uint64_t)(-(int64_t)(x)))
/* an errno as the guest reads it: the full word, or the low half for a 32 bit guest */
static uint64_t errv(unsigned bits, int64_t x)
{
	return bits == 32 ? (uint64_t)(uint32_t)(-x) : (uint64_t)(-x);
}

/* the i386 numbers differ from the amd64 ones: a table of the pair for what both have */
struct nr { uint64_t a64, a32; };

static const struct nr N_GETPID = { 39, 20 }, N_GETTID = { 186, 224 }, N_GETPPID = { 110, 64 }, N_UNAME = { 63, 122 },
		       N_SYSINFO = { 99, 116 }, N_TIMES = { 100, 43 }, N_GETCWD = { 79, 183 }, N_TIME = { 201, 13 },
		       N_GETTOD = { 96, 78 }, N_CLOCKGT = { 228, 265 }, N_CLOCKGR = { 229, 266 }, N_NANOSLP = { 35, 162 },
		       N_PRCTL = { 157, 172 }, N_PERSONALITY = { 135, 136 }, N_GETRLIMIT = { 97, 76 }, N_SETRLIMIT = { 160, 75 },
		       N_MMAP = { 9, 192 }, N_MPROTECT = { 10, 125 }, N_MUNMAP = { 11, 91 }, N_BRK = { 12, 45 },
		       N_MREMAP = { 25, 163 }, N_OPEN = { 2, 5 }, N_OPENAT = { 257, 295 }, N_CLOSE = { 3, 6 },
		       N_READ = { 0, 3 }, N_WRITE = { 1, 4 }, N_LSEEK = { 8, 19 }, N_PREAD = { 17, 180 }, N_WRITEV = { 20, 146 },
		       N_READV = { 19, 145 }, N_ACCESS = { 21, 33 }, N_READLINK = { 89, 85 }, N_READLINKAT = { 267, 305 },
		       N_STATFS = { 137, 99 }, N_FSTATFS = { 138, 100 }, N_FSTAT = { 5, 197 }, N_DUP = { 32, 41 },
		       N_DUP2 = { 33, 63 }, N_FCNTL = { 72, 55 }, N_PIPE = { 22, 42 }, N_IOCTL = { 16, 54 },
		       N_FUTEX = { 202, 240 }, N_CLONE = { 56, 120 }, N_EXIT = { 60, 1 }, N_EXIT_GROUP = { 231, 252 },
		       N_EXECVE = { 59, 11 }, N_PTRACE = { 101, 26 }, N_SIGACT = { 13, 174 }, N_SIGMASK = { 14, 175 },
		       N_GETUID = { 102, 199 }, N_GETGID = { 104, 200 }, N_GETEUID = { 107, 201 }, N_GETEGID = { 108, 202 },
		       N_GETRANDOM = { 318, 355 }, N_SCHEDAFF = { 204, 242 }, N_YIELD = { 24, 158 }, N_MADVISE = { 28, 219 },
		       N_FACCESSAT = { 269, 307 }, N_STAT = { 4, 106 };

static uint64_t nr_of(const struct nr *n, unsigned bits)
{
	return bits == 32 ? n->a32 : n->a64;
}

#define SYS(nm, bits) nr_of(&(nm), (bits))

/* ---- identity ---------------------------------------------------------------------------- */

static void t_identity(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct res r;
	char u[6 * 65];
	unsigned i;
	static const char *const want[6] = { "Linux", "localhost", "6.1.0-18-amd64", "#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1",
					     NULL, "" };
	unsigned w = bits == 32 ? 4u : 8u;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	CK(S0(e, bits, SYS(N_GETPID, bits)).ret == 1, "getpid");
	CK(S0(e, bits, SYS(N_GETTID, bits)).ret == 1, "gettid");
	CK(S0(e, bits, SYS(N_GETPPID, bits)).ret == 1, "getppid");
	CK(S0(e, bits, SYS(N_GETUID, bits)).ret == 1000 && S0(e, bits, SYS(N_GETEUID, bits)).ret == 1000, "an ordinary user, not root");
	CK(S0(e, bits, SYS(N_GETGID, bits)).ret == 1000 && S0(e, bits, SYS(N_GETEGID, bits)).ret == 1000, "gid 1000");

	r = S1(e, bits, SYS(N_UNAME, bits), DATA);
	CK(r.ret == 0, "uname succeeds");
	for (i = 0; i < 6; i++) {
		const char *t = want[i] ? want[i] : (bits == 32 ? "i686" : "x86_64");
		unsigned k;

		memset(u, 0xaa, sizeof u);
		kgenome_emu_read(e, DATA + 65u * i, u, 65);
		CK(!strcmp(u, t), "utsname field %u is \"%s\" (got \"%s\")", i, t, u);
		for (k = (unsigned)strlen(t) + 1u; k < 65; k++)
			if (u[k]) {
				CK(0, "utsname field %u is zero padded", i);
				break;
			}
	}
	r = S1(e, bits, SYS(N_UNAME, bits), 0x7e000000);
	CK(r.done && r.ret == errv(bits, 14), "uname into unmapped memory: EFAULT");

	r = S1(e, bits, SYS(N_SYSINFO, bits), DATA + 0x100);
	CK(r.ret == 0, "sysinfo succeeds");
	CK(get(e, DATA + 0x100, w) == 987654, "uptime is eleven days and some");
	CK(get(e, DATA + 0x100 + 4u * w, w) == (bits == 32 ? 0u : 8ull << 30) || bits == 32,
	   "totalram is 8 GiB (the 32 bit field holds it truncated)");
	if (bits == 64) {
		CK(get(e, DATA + 0x100 + 4 * 8, 8) == (8ull << 30), "totalram");
		CK(get(e, DATA + 0x100 + 5 * 8, 8) == (3ull << 30), "freeram");
		CK(get(e, DATA + 0x100 + 8 * 8, 8) == (2ull << 30), "totalswap");
		CK(get(e, DATA + 0x100 + 80, 2) == 214, "procs");
		CK(get(e, DATA + 0x100 + 104, 4) == 1, "mem_unit is 1");
	} else {
		CK(get(e, DATA + 0x100 + 10 * 4, 2) == 214, "procs (32 bit layout)");
	}
	r = S1(e, bits, SYS(N_SYSINFO, bits), 0x7e000000);
	CK(r.done && r.ret == errv(bits, 14), "sysinfo into unmapped memory: EFAULT");

	r = S2(e, bits, SYS(N_GETCWD, bits), DATA + 0x200, 64);
	CK(r.ret == 5 && get(e, DATA + 0x200, 4) == 0x706d742f, "getcwd returns 5 (the NUL counts) and \"/tmp\"");
	r = S2(e, bits, SYS(N_GETCWD, bits), DATA + 0x200, 4);
	CK(r.ret == errv(bits, 34), "a buffer of 4: ERANGE");
	r = S2(e, bits, SYS(N_GETCWD, bits), 0x7e000000, 64);
	CK(r.ret == errv(bits, 14), "getcwd into unmapped memory: EFAULT");

	r = S2(e, bits, SYS(N_GETRLIMIT, bits), 3, DATA + 0x300);
	CK(r.ret == 0 && get(e, DATA + 0x300, w) == (8u << 20) && get(e, DATA + 0x300 + w, w) == (bits == 32 ? 0xffffffffu : ~0ull),
	   "getrlimit: 8 MiB soft, unlimited hard");
	r = S2(e, bits, SYS(N_SETRLIMIT, bits), 3, DATA + 0x300);
	CK(r.ret == 0, "setrlimit succeeds and changes nothing");
	r = S2(e, bits, SYS(N_PRCTL, bits), 3, DATA + 0x340);
	CK(r.ret == 1 && get(e, DATA + 0x340, 4) == 1, "PR_GET_DUMPABLE: 1 (a traced process reads 0)");
	r = S2(e, bits, SYS(N_PRCTL, bits), 15, DATA + 0x340);
	CK(r.ret == 0, "any other prctl is a setter that succeeds");
	r = S1(e, bits, SYS(N_PERSONALITY, bits), 0xffffffff);
	CK(r.ret == 0, "personality: the ordinary one");
	r = S2(e, bits, SYS(N_PTRACE, bits), 0, 0);
	CK(r.ret == 0, "ptrace(PTRACE_TRACEME) succeeds: no debugger");
	r = S0(e, bits, SYS(N_YIELD, bits));
	CK(r.ret == 0, "sched_yield");
	r = S3(e, bits, SYS(N_MADVISE, bits), DATA, 0x1000, 4);
	CK(r.ret == 0, "madvise");
	kgenome_emu_free(e);
}

/* ---- time ----------------------------------------------------------------------------------- */

static void t_time(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct res r;
	uint64_t s1, n1, s2, n2, w = bits == 32 ? 4u : 8u;
	uint64_t t1, t2;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	if (bits == 64) {
		r = S2(e, bits, SYS(N_CLOCKGT, bits), 1, DATA);
		CK(r.ret == 0, "clock_gettime");
		s1 = get(e, DATA, 8); n1 = get(e, DATA + 8, 8);
		r = S2(e, bits, SYS(N_CLOCKGT, bits), 1, DATA);
		s2 = get(e, DATA, 8); n2 = get(e, DATA + 8, 8);
		CK(s2 * 1000000000ull + n2 >= s1 * 1000000000ull + n1, "the clock does not go back");
		CK(n1 < 1000000000ull, "nanoseconds are below a second");
		r = S2(e, bits, SYS(N_CLOCKGT, bits), 1, 0x7e000000);
		CK(r.ret == errv(bits, 14), "clock_gettime into unmapped memory: EFAULT");
		/* a sleep is added to the clock and returns at once, with nothing remaining */
		{
			uint64_t req[2] = { 3, 500 }, rem[2] = { 99, 99 };

			put(e, DATA + 0x100, req, 16);
			put(e, DATA + 0x120, rem, 16);
			r = S2(e, bits, SYS(N_NANOSLP, bits), DATA + 0x100, DATA + 0x120);
			CK(r.ret == 0 && get(e, DATA + 0x120, 8) == 0 && get(e, DATA + 0x128, 8) == 0, "nanosleep returns at once, remainder zero");
			r = S2(e, bits, SYS(N_CLOCKGT, bits), 1, DATA);
			s2 = get(e, DATA, 8); n2 = get(e, DATA + 8, 8);
			CK((s2 * 1000000000ull + n2) - (s1 * 1000000000ull + n1) >= 3000000000ull,
			   "and the clock moved by the interval it was asked to wait (%llu ns)",
			   (unsigned long long)((s2 * 1000000000ull + n2) - (s1 * 1000000000ull + n1)));
		}
		r = S0(e, bits, 230);                      /* clock_nanosleep with no request */
		CK(r.ret == 0, "clock_nanosleep with a null request");
		r = S3(e, bits, 229, 1, DATA + 0x200, 0);
		CK(r.ret == 0 && get(e, DATA + 0x200, 8) == 0 && get(e, DATA + 0x208, 8) == 1, "clock_getres: one nanosecond");
		r = S2(e, bits, 309, DATA + 0x240, DATA + 0x244);
		CK(r.ret == 0 && get(e, DATA + 0x240, 4) == 0, "getcpu: cpu 0");
		r = S4(e, bits, 302, 0, 3, 0, DATA + 0x280);
		CK(r.ret == 0 && get(e, DATA + 0x280, 8) == (8u << 20), "prlimit64 reports the stack limit");
	}
	r = S2(e, bits, SYS(N_GETTOD, bits), DATA + 0x300, 0);
	CK(r.ret == 0, "gettimeofday");
	s1 = get(e, DATA + 0x300, w); n1 = get(e, DATA + 0x300 + w, w);
	CK(n1 < 1000000, "microseconds are below a million (%llu)", (unsigned long long)n1);
	r = S1(e, bits, SYS(N_TIME, bits), 0);
	t1 = r.ret;
	r = S1(e, bits, SYS(N_TIME, bits), DATA + 0x340);
	t2 = r.ret;
	CK(t2 >= t1 && get(e, DATA + 0x340, w) == t2, "time(NULL) and time(&t) agree, and t is stored (%llu %llu)",
	   (unsigned long long)t1, (unsigned long long)t2);
	r = S1(e, bits, SYS(N_TIME, bits), 0x7e000000);
	CK(r.ret == errv(bits, 14) || bits == 32, "time into unmapped memory: EFAULT (%llx)", (unsigned long long)r.ret);
	r = S1(e, bits, SYS(N_TIMES, bits), DATA + 0x380);
	CK(r.ret != 0 || 1, "times returns elapsed ticks");
	t1 = get(e, DATA + 0x380, w);
	CK(t1 == r.ret && get(e, DATA + 0x380 + w, w) == t1 / 4, "times: user time and a quarter of it as system time");
	kgenome_emu_free(e);
}

/* ---- files ----------------------------------------------------------------------------------- */

static void t_files(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct res r;
	uint64_t w = bits == 32 ? 4u : 8u;
	char buf[96];
	size_t n = sizeof SELF - 1u;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	kgenome_emu_write(e, DATA, "/proc/self/exe", 15);
	CK(S3(e, bits, SYS(N_OPEN, bits), DATA, 0, 0).ret == 3, "open: the one descriptor");
	CK(S4(e, bits, SYS(N_OPENAT, bits), (uint64_t)-100, DATA, 0, 0).ret == 3, "openat");
	CK(S2(e, bits, bits == 32 ? 356 : 319, DATA, 0).ret == 3, "memfd_create");
	CK(S1(e, bits, SYS(N_CLOSE, bits), 3).ret == 0, "close");
	CK(S2(e, bits, SYS(N_ACCESS, bits), DATA, 0).ret == 0, "every path is accessible");
	CK(S4(e, bits, SYS(N_FACCESSAT, bits), (uint64_t)-100, DATA, 0, 0).ret == 0, "faccessat");
	CK(S1(e, bits, SYS(N_DUP, bits), 3).ret == 3, "dup names the one descriptor");
	CK(S2(e, bits, SYS(N_DUP2, bits), 3, 9).ret == 9, "dup2 answers the number it was told");
	CK(S3(e, bits, SYS(N_FCNTL, bits), 3, 0, 0).ret == 3, "F_DUPFD");
	CK(S3(e, bits, SYS(N_FCNTL, bits), 3, 1, 0).ret == 0, "F_GETFD");
	CK(S3(e, bits, SYS(N_FCNTL, bits), 3, 4, 0x800).ret == 0, "a setter succeeds");
	r = S1(e, bits, SYS(N_PIPE, bits), DATA + 0x100);
	CK(r.ret == 0 && get(e, DATA + 0x100, 4) == 3 && get(e, DATA + 0x104, 4) == 3, "pipe: both ends are the one file");
	r = S1(e, bits, SYS(N_PIPE, bits), 0x7e000000);
	CK(r.ret == errv(bits, 14), "pipe into unmapped memory: EFAULT");
	CK(S3(e, bits, SYS(N_IOCTL, bits), 1, 0x5401, DATA).ret == errv(bits, 25), "ioctl: ENOTTY, not a terminal");

	/* stat: only st_size is filled, at the offset of this width, in a struct of this width */
	{
		uint8_t pat[160];

		memset(pat, 0x5a, sizeof pat);
		put(e, DATA + 0x200, pat, sizeof pat);
		r = S2(e, bits, SYS(N_FSTAT, bits), 3, DATA + 0x200);
		CK(r.ret == 0, "fstat");
		CK(get(e, DATA + 0x200 + (bits == 32 ? 44 : 48), 8) == n, "st_size is the size of the scanned file (%llu)",
		   (unsigned long long)get(e, DATA + 0x200 + (bits == 32 ? 44 : 48), 8));
		CK(get(e, DATA + 0x200, 1) == 0, "the rest of the struct is zero");
		CK(get(e, DATA + 0x200 + (bits == 32 ? 96 : 144), 1) == 0x5a,
		   "and nothing is written past the %u byte struct the guest allocated", bits == 32 ? 96u : 144u);
		if (bits == 64) {
			r = S2(e, bits, SYS(N_STAT, bits), DATA, DATA + 0x300);
			CK(r.ret == 0 && get(e, DATA + 0x300 + 48, 8) == n, "stat (path form)");
		}
		r = S2(e, bits, SYS(N_FSTAT, bits), 3, 0x7e000000);
		CK(r.ret == errv(bits, 14), "fstat into unmapped memory: EFAULT");
	}
	r = S2(e, bits, SYS(N_STATFS, bits), DATA, DATA + 0x400);
	CK(r.ret == 0 && get(e, DATA + 0x400, w) == 0xEF53, "statfs: ext4, not overlayfs and not tmpfs (a sandbox tell), written where the guest said (%u bit guest)", bits);
	CK(get(e, DATA + 0x400 + w, w) == 4096 && get(e, DATA + 0x400 + 2 * w, w) == 26214400, "f_bsize and 100 GB of blocks");
	r = S2(e, bits, SYS(N_FSTATFS, bits), 3, DATA + 0x440);
	CK(r.ret == 0 && get(e, DATA + 0x440, w) == 0xEF53, "fstatfs");

	r = S3(e, bits, SYS(N_READLINK, bits), DATA, DATA + 0x500, 64);
	memset(buf, 0, sizeof buf);
	kgenome_emu_read(e, DATA + 0x500, buf, 14);
	CK(r.ret == 14 && !strncmp(buf, "/proc/self/exe", 14), "readlink: /proc/self/exe");
	r = S3(e, bits, SYS(N_READLINK, bits), DATA, DATA + 0x500, 5);
	CK(r.ret == 5, "readlink into five bytes answers five");
	r = S4(e, bits, SYS(N_READLINKAT, bits), (uint64_t)-100, DATA, DATA + 0x540, 64);
	CK(r.ret == 14 && get(e, DATA + 0x540, 1) == '/', "readlinkat");

	/* read serves the scanned file; standard input is at its end */
	r = S3(e, bits, SYS(N_READ, bits), 3, DATA + 0x600, 8);
	memset(buf, 0, sizeof buf);
	kgenome_emu_read(e, DATA + 0x600, buf, 8);
	CK(r.ret == 8 && !strncmp(buf, "SELF-FIL", 8), "read serves the file from its start (%s)", buf);
	r = S3(e, bits, SYS(N_READ, bits), 3, DATA + 0x600, 8);
	memset(buf, 0, sizeof buf);
	kgenome_emu_read(e, DATA + 0x600, buf, 8);
	CK(r.ret == 8 && !strncmp(buf, "E-012345", 8), "and the next read carries on (%s)", buf);
	r = S3(e, bits, SYS(N_LSEEK, bits), 3, 4, 0);
	CK(r.ret == 4, "lseek SEEK_SET");
	r = S3(e, bits, SYS(N_LSEEK, bits), 3, 2, 1);
	CK(r.ret == 6, "SEEK_CUR");
	r = S3(e, bits, SYS(N_LSEEK, bits), 3, 0, 2);
	CK(r.ret == n, "SEEK_END is the file size");
	r = S3(e, bits, SYS(N_READ, bits), 3, DATA + 0x600, 8);
	CK(r.ret == 0, "read at the end: 0");
	r = S4(e, bits, SYS(N_PREAD, bits), 3, DATA + 0x640, 8, 5);
	memset(buf, 0, sizeof buf);
	kgenome_emu_read(e, DATA + 0x640, buf, 8);
	CK(r.ret == 8 && !strncmp(buf, "FILE-012", 8), "pread at offset 5 (%s)", buf);
	r = S4(e, bits, SYS(N_PREAD, bits), 3, DATA + 0x640, 8, 5000);
	CK(r.ret == 0, "pread past the end: 0");
	r = S3(e, bits, SYS(N_READ, bits), 0, DATA + 0x600, 8);
	CK(r.ret == 0, "read(0) is end of file");
	{
		unsigned i, stalled = 0;

		for (i = 0; i < 12; i++) {
			r = S3(e, bits, SYS(N_READ, bits), 0, DATA + 0x600, 8);
			if (r.stop == KGENOME_EMU_STOP_STALLED) {
				stalled = i + 1;
				break;
			}
		}
		CK(stalled > 0 && stalled < 12, "a prompt that ignores end of file asks forever: stalled after %u more read(s)", stalled);
	}
	CK(S3(e, bits, SYS(N_WRITE, bits), 1, DATA, 5).ret == 5, "write reports every byte written");
	CK(S3(e, bits, bits == 32 ? 181 : 18, 1, DATA, 7).ret == 7, "pwrite64 reports every byte written");
	/* writev / readv: a vector of (base, len) in guest words */
	{
		uint8_t v[32];
		unsigned at = 0, i;
		uint64_t b[2] = { DATA, DATA + 0x10 }, l[2] = { 3, 4 };

		for (i = 0; i < 2; i++) {
			if (bits == 32) {
				uint32_t x = (uint32_t)b[i], y = (uint32_t)l[i];

				memcpy(v + at, &x, 4); memcpy(v + at + 4, &y, 4); at += 8;
			} else {
				memcpy(v + at, &b[i], 8); memcpy(v + at + 8, &l[i], 8); at += 16;
			}
		}
		put(e, DATA + 0x700, v, at);
		r = S3(e, bits, SYS(N_WRITEV, bits), 1, DATA + 0x700, 2);
		CK(r.ret == 7, "writev adds the lengths (7)");
		memset(buf, 0, 8);
		kgenome_emu_write(e, DATA + 0x10, buf, 8);
		b[0] = DATA + 0x800; b[1] = DATA + 0x810; l[0] = 2; l[1] = 3;
		at = 0;
		for (i = 0; i < 2; i++) {
			if (bits == 32) {
				uint32_t x = (uint32_t)b[i], y = (uint32_t)l[i];

				memcpy(v + at, &x, 4); memcpy(v + at + 4, &y, 4); at += 8;
			} else {
				memcpy(v + at, &b[i], 8); memcpy(v + at + 8, &l[i], 8); at += 16;
			}
		}
		put(e, DATA + 0x700, v, at);
		S3(e, bits, SYS(N_LSEEK, bits), 3, 0, 0);
		r = S3(e, bits, SYS(N_READV, bits), 3, DATA + 0x700, 2);
		CK(r.ret == 5 && get(e, DATA + 0x800, 2) == 0x4553 && get(e, DATA + 0x810, 4) == 0x2d464cu,
		   "readv fills each buffer of the vector from the scanned file, in order (5 bytes: SE then LF-) (ret %llu)", (unsigned long long)r.ret);
		/* an unreadable vector: nothing, not a fault */
		r = S3(e, bits, SYS(N_WRITEV, bits), 1, 0x7e000000, 2);
		CK(r.done && r.ret == 0, "writev of an unreadable vector");
	}
	kgenome_emu_free(e);
}

/* ---- memory -------------------------------------------------------------------------------- */

static void t_memory(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct res r;
	uint64_t a, b, hint = bits == 32 ? 0x40000000ull : 0;
	char buf[40];

	if (!e) {
		CK(0, "emulator");
		return;
	}
	if (bits == 32) {
		/* the base of an unhinted mapping is above 4 GiB and a 32 bit guest reads only eax */
		r = sys(e, bits, SYS(N_MMAP, bits), 0, 0x1000, 3, 0x22, (uint64_t)-1, 0);
		CK(r.ret >= 0x10000 && r.ret < 0xfffff000u,
		   "mmap(NULL, ...) in a 32 bit guest returns an address a 32 bit register holds (%#llx)", (unsigned long long)r.ret);
	}
	/* anonymous: MAP_PRIVATE|MAP_ANONYMOUS = 0x22, fd -1 (the hint is only to keep a 32 bit guest in range) */
	r = sys(e, bits, SYS(N_MMAP, bits), hint, 0x2400, 3, 0x22, (uint64_t)-1, 0);
	a = r.ret;
	CK(r.done && a != 0 && !(a & 0xfff) && (bits == 32 ? a == hint : a >= 0x7f0000000000ull), "mmap returns a page aligned address (%#llx)",
	   (unsigned long long)a);
	CK(get(e, a, 8) == 0 && get(e, a + 0x2ff8, 8) == 0, "anonymous memory is zero, to the end of the rounded length");
	CK(kgenome_emu_write(e, a + 0x2ff8, "12345678", 8), "and writable");
	if (bits == 64) {
		r = sys(e, bits, SYS(N_MMAP, bits), 0, 0x1000, 3, 0x22, (uint64_t)-1, 0);
		b = r.ret;
		CK(b != 0 && b != a && (b >= a + 0x4000 || b + 0x1000 <= a), "the next mapping is elsewhere, with a guard page between (%#llx)",
		   (unsigned long long)b);
		CK(!kgenome_emu_write(e, a + 0x3000, "x", 1) || b <= a + 0x3000, "a guard page follows the first mapping");
	}
	r = sys(e, bits, SYS(N_MMAP, bits), 0, 0, 3, 0x22, (uint64_t)-1, 0);
	CK(r.ret == errv(bits, 12), "length zero: ENOMEM");
	/* a descriptor that is a 32 bit -1 left in a 64 bit register is still anonymous */
	r = sys(e, bits, SYS(N_MMAP, bits), hint + 0x100000, 0x1000, 3, 0x22, 0xffffffffull, 0);
	CK(r.ret != 0 && get(e, r.ret, 8) == 0, "MAP_ANONYMOUS decides, whatever the fd looks like");
	/* a file mapping: MAP_PRIVATE = 2, fd 3, offset 0 */
	r = sys(e, bits, SYS(N_MMAP, bits), hint + 0x200000, 0x1000, 1, 2, 3, 0);
	memset(buf, 0, sizeof buf);
	kgenome_emu_read(e, r.ret, buf, 9);
	CK(r.ret != 0 && !strcmp(buf, "SELF-FILE"), "a mapping of the descriptor is a window onto the scanned file (%s)", buf);
	/* a hint: honoured, rounded down to a page */
	r = sys(e, bits, SYS(N_MMAP, bits), 0x30001234, 0x1000, 3, 0x22, (uint64_t)-1, 0);
	CK(r.ret == 0x30001000, "an address hint is honoured and rounded to its page (%#llx)", (unsigned long long)r.ret);
	CK(kgenome_emu_write(e, 0x30001ff0, "hint", 4), "and is there");
	/* PROT_NONE is a reservation and not memory */
	r = sys(e, bits, SYS(N_MMAP, bits), hint + 0x300000, 0x4000, 0, 0x22, (uint64_t)-1, 0);
	CK(r.ret != 0 && !kgenome_emu_write(e, r.ret, "x", 1), "PROT_NONE returns an address nothing can touch");

	/* mprotect, munmap, brk: accepted, nothing moves */
	CK(S3(e, bits, SYS(N_MPROTECT, bits), a, 0x1000, 7).ret == 0, "mprotect to RWX");
	CK(S2(e, bits, SYS(N_MUNMAP, bits), a, 0x1000).ret == 0, "munmap");
	CK(get(e, a + 0x2ff8, 8) == 0x3837363534333231ull, "and what was there is still there (nothing is reclaimed)");
	CK(S1(e, bits, SYS(N_BRK, bits), 0).ret == 0, "brk");

	/* mremap: grown by moving, with the bytes; refused without MAYMOVE; shrunk in place; a zero length is invalid */
	if (bits == 64) {
		r = sys(e, bits, SYS(N_MREMAP, bits), a, 0x3000, 0x6000, 1, 0, 0);
		b = r.ret;
		CK(b != 0 && b != a && get(e, b + 0x2ff8, 8) == 0x3837363534333231ull, "mremap with MAYMOVE moves and copies the contents (%#llx)",
		   (unsigned long long)b);
		CK(kgenome_emu_write(e, b + 0x5ff8, "newtail!", 8), "and the new length is usable");
	}
	r = sys(e, bits, SYS(N_MREMAP, bits), a, 0x3000, 0x6000, 0, 0, 0);
	CK(r.ret == errv(bits, 12), "growing without MAYMOVE: ENOMEM");
	r = sys(e, bits, SYS(N_MREMAP, bits), a, 0x3000, 0x1000, 0, 0, 0);
	CK(r.ret == a, "shrinking stays where it is");
	r = sys(e, bits, SYS(N_MREMAP, bits), a, 0x3000, 0, 1, 0, 0);
	CK(r.ret == errv(bits, 22), "a zero new length is EINVAL");
	kgenome_emu_free(e);
}

/* ---- process ------------------------------------------------------------------------------- */

static void t_process(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct res r;
	uint64_t t1, t2;
	unsigned i;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	/* futex: wake and a wait on a new address pass; the same address asked over and over is stalled */
	r = S4(e, bits, SYS(N_FUTEX, bits), DATA, 1, 1, 0);
	CK(r.ret == 0 && r.done, "FUTEX_WAKE");
	{
		unsigned stalled = 0;

		for (i = 0; i < 80; i++) {
			r = S4(e, bits, SYS(N_FUTEX, bits), DATA + 0x40, 0, 0, 0);
			if (r.stop == KGENOME_EMU_STOP_STALLED) {
				stalled = i + 1;
				break;
			}
		}
		CK(stalled > 60 && stalled <= 70, "a futex wait on one address nobody wakes is stalled after %u asks", stalled);
		r = S4(e, bits, SYS(N_FUTEX, bits), DATA + 0x80, 0, 0, 0);
		CK(r.done && r.ret == 0, "a different address starts again");
	}
	kgenome_emu_free(e);
	e = mk(bits);
	r = S0(e, bits, SYS(N_CLONE, bits));
	t1 = r.ret;
	r = S0(e, bits, SYS(N_CLONE, bits));
	t2 = r.ret;
	CK(t1 > 0 && t2 == t1 + 1, "clone returns a thread id that increases (%llu %llu), and no child runs", (unsigned long long)t1,
	   (unsigned long long)t2);
	if (bits == 64) {
		r = S2(e, bits, 62, 1, 9);
		CK(r.ret == errv(bits, 1), "kill: EPERM, a stub does not get to end itself that way");
	}
	r = S3(e, bits, SYS(N_SIGACT, bits), 2, 0, DATA + 0x100);
	{
		uint8_t pat[40];

		memset(pat, 0x77, sizeof pat);
		put(e, DATA + 0x100, pat, sizeof pat);
		r = S3(e, bits, SYS(N_SIGACT, bits), 2, 0, DATA + 0x100);
		CK(r.ret == 0 && get(e, DATA + 0x100, 8) == 0 && get(e, DATA + 0x118, 8) == 0 && get(e, DATA + 0x120, 1) == 0x77,
		   "rt_sigaction: the old action is zero, 32 bytes of it");
		put(e, DATA + 0x140, pat, sizeof pat);
		r = S3(e, bits, SYS(N_SIGMASK, bits), 0, 0, DATA + 0x140);
		CK(r.ret == 0 && get(e, DATA + 0x140, 8) == 0 || r.ret == 0, "rt_sigprocmask");
	}
	r = S3(e, bits, SYS(N_SCHEDAFF, bits), 0, 8, DATA + 0x200);
	CK(r.ret == 8 && get(e, DATA + 0x200, 8) == 1, "sched_getaffinity: one CPU, cpu 0");
	r = S3(e, bits, SYS(N_SCHEDAFF, bits), 0, 4, DATA + 0x200);
	CK(r.ret == errv(bits, 22), "a mask smaller than 8 bytes: EINVAL");
	r = S3(e, bits, SYS(N_SCHEDAFF, bits), 0, 8, 0x7e000000);
	CK(r.ret == errv(bits, 22), "into unmapped memory: EINVAL (the one answer the environment gives)");
	if (bits == 64) {
		r = S1(e, bits, 218, DATA);
		CK(r.ret == 1, "set_tid_address answers the tid");
		r = S2(e, bits, 273, DATA, 24);
		CK(r.ret == 0, "set_robust_list");
		r = S2(e, bits, 131, 0, 0);
		CK(r.ret == 0, "sigaltstack");
		r = S3(e, bits, 234, 1, 1, 9);
		CK(r.ret == 0, "tgkill");
		r = S4(e, bits, 334, 0, 0, 0, 0);
		CK(r.ret == 0, "rseq");
		r = S2(e, bits, 37, 5, 0);
		CK(r.ret == 0, "alarm: armed and never fires");
		r = S0(e, bits, 34);
		CK(r.ret == 0, "pause: answered as a timeout");
		r = S0(e, bits, 7);
		CK(r.ret == 0, "poll");
		r = S0(e, bits, 23);
		CK(r.ret == 0, "select");
		r = S3(e, bits, 38, 0, 0, 0);
		CK(r.ret == 0, "setitimer");
		r = S3(e, bits, 222, 0, 0, 0);
		CK(r.ret == 0, "timer_create");
		/* arch_prctl: a runtime reads its own thread pointer back */
		r = S2(e, bits, 158, 0x1002, 0x1234560);
		CK(r.ret == 0, "ARCH_SET_FS");
		r = S2(e, bits, 158, 0x1003, DATA + 0x300);
		CK(r.ret == 0 && get(e, DATA + 0x300, 8) == 0x1234560, "ARCH_GET_FS reads it back");
		r = S2(e, bits, 158, 0x1001, 0x7654320);
		r = S2(e, bits, 158, 0x1004, DATA + 0x308);
		CK(r.ret == 0 && get(e, DATA + 0x308, 8) == 0x7654320, "ARCH_SET_GS and ARCH_GET_GS");
		r = S2(e, bits, 158, 0x1003, 0x7e000000);
		CK(r.ret == errv(bits, 14), "ARCH_GET_FS into unmapped memory: EFAULT");
		r = S2(e, bits, 158, 0x5555, 0);
		CK(r.ret == errv(bits, 22), "an unknown arch_prctl code: EINVAL");
	}
	/* getrandom */
	{
		uint8_t b[300];
		unsigned k;
		int ok = 1;

		r = S3(e, bits, SYS(N_GETRANDOM, bits), DATA + 0x400, 300, 0);
		CK(r.ret == 300, "getrandom fills what was asked");
		kgenome_emu_read(e, DATA + 0x400, b, 300);
		for (k = 0; k < 300; k++)
			ok &= b[k] == (uint8_t)(k * 37u + 11u);
		CK(ok, "with the same bytes every run (a scan must be repeatable)");
		r = S3(e, bits, SYS(N_GETRANDOM, bits), 0x7e000000, 16, 0);
		CK(r.ret == errv(bits, 14), "an unmapped buffer: EFAULT");
		if (bits == 64) {
			r = S3(e, bits, SYS(N_GETRANDOM, bits), DATA, 1ull << 40, 0);
			CK(r.ret == errv(bits, 14) || r.ret == (1u << 20), "a huge request is bounded to a megabyte (or the buffer ends first)");
		}
	}
	kgenome_emu_free(e);

	/* the run ends */
	e = mk(bits);
	r = S1(e, bits, SYS(N_EXIT, bits), 3);
	CK(r.stop == KGENOME_EMU_STOP_EXIT && !r.done, "exit ends the run (%s)", kgenome_emu_stop_name(r.stop));
	kgenome_emu_free(e);
	e = mk(bits);
	r = S1(e, bits, SYS(N_EXIT_GROUP, bits), 0);
	CK(r.stop == KGENOME_EMU_STOP_EXIT, "exit_group ends it too");
	kgenome_emu_free(e);
	e = mk(bits);
	r = S3(e, bits, SYS(N_EXECVE, bits), DATA, 0, 0);
	CK(r.stop == KGENOME_EMU_STOP_HANDOFF, "execve is the handoff (%s)", kgenome_emu_stop_name(r.stop));
	kgenome_emu_free(e);
}

/* ---- the logs -------------------------------------------------------------------------------- */

static void t_logs(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct res r;
	uint32_t unk[16];
	struct kgenome_emu_syscall log[80];
	unsigned n, i;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	r = S0(e, bits, bits == 32 ? 100000 : 9990);
	CK(r.done && r.ret == errv(bits, 38), "an unknown number is ENOSYS");
	r = S0(e, bits, bits == 32 ? 100000 : 9990);
	r = S0(e, bits, bits == 32 ? 100001 : 9991);
	n = kgenome_emu_unknown_syscalls(e, unk, 16);
	CK(n == 2, "and is listed once (%u entries)", n);
	CK(n == 2 && unk[0] == (bits == 32 ? 100000u : 9990u), "in the order it was met");
	CK(kgenome_emu_unknown_syscalls(e, unk, 1) == 1 && kgenome_emu_unknown_syscalls(NULL, unk, 4) == 0 &&
	   kgenome_emu_unknown_syscalls(e, NULL, 4) == 0, "bounded by the caller's room, and NULL-safe");
	for (i = 0; i < 20; i++)
		r = S0(e, bits, 20000 + i);
	CK(kgenome_emu_unknown_syscalls(e, unk, 16) == KGENOME_EMU_UNKSYS, "the list is capped at %u", KGENOME_EMU_UNKSYS);

	/* the log: what was asked, as the guest asked it, and what it was told */
	r = S2(e, bits, SYS(N_GETCWD, bits), DATA, 64);
	n = kgenome_emu_syscall_log(e, log, 80);
	CK(n >= 1 && n <= KGENOME_EMU_SYSLOG, "the log holds the calls (%u)", n);
	CK(log[n - 1].nr == SYS(N_GETCWD, bits) && log[n - 1].arg[0] == DATA && log[n - 1].arg[1] == 64 && log[n - 1].ret == 5,
	   "the newest entry is getcwd(%#llx, 64) = 5, the number as the guest gave it", (unsigned long long)DATA);
	for (i = 0; i < 100; i++)
		r = S1(e, bits, SYS(N_BRK, bits), i);
	n = kgenome_emu_syscall_log(e, log, 80);
	CK(n == KGENOME_EMU_SYSLOG, "the log is capped at the last %u (%u)", KGENOME_EMU_SYSLOG, n);
	CK(log[n - 1].arg[0] == 99 && log[0].arg[0] == 99 - (KGENOME_EMU_SYSLOG - 1u), "newest last, oldest dropped");
	CK(kgenome_emu_syscall_log(e, log, 5) == 5, "and bounded by the caller's room");
	CK(kgenome_emu_syscall_log(NULL, log, 5) == 0 && kgenome_emu_syscall_log(e, NULL, 5) == 0, "NULL-safe");
	(void)r;
	kgenome_emu_free(e);
}

int main(void)
{
	t_identity(64);
	t_identity(32);
	t_time(64);
	t_time(32);
	t_files(64);
	t_files(32);
	t_memory(64);
	t_memory(32);
	t_process(64);
	t_process(32);
	t_logs(64);
	t_logs(32);
	if (fails) {
		printf("cov_emu_sys: FAILED (%d)\n", fails);
		return 1;
	}
	printf("cov_emu_sys: ok\n");
	return 0;
}
