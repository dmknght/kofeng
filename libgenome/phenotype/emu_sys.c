/*
 * emu_sys.c - the Linux environment: the syscall dispatcher, and the clock a guest reads.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"


/*
 * Roughly a cycle per instruction, which is what a real machine retires. The
 * number only has to keep the ratio between two readings believable.
 */
#define TSC_PER_INSN  1u

/* The jump a recognised delay loop is granted, doubling while it persists. */
#define TSC_SPIN_MIN  (1u << 16)
#define TSC_SPIN_AT   8u
/*
 * The widest gap between two clock reads that may still be called a wait.
 *
 * Not a tuning knob so much as the line between "looking busy" and "being
 * busy". Padding a delay loop is free - nops, dead arithmetic, an opaque
 * predicate - so any bound here can be padded past; what cannot be padded past
 * is the productivity test beside it, and this exists only so that a loop doing
 * thousands of instructions of genuine register work per iteration is left to
 * run at the honest rate.
 */
#define TSC_SPIN_GAP  4096u

uint64_t kgenome_emu_tsc_read(struct kgenome_emu *e)
{
	uint64_t gap = e->insn - e->tsc_last_insn;
	/*
	 * A WAIT IS A READ THAT FOLLOWS NO PROGRESS, not a read that follows
	 * few instructions - see tsc_last_page.
	 *
	 * The instruction gap stays as a GUARD rather than as the test. A loop
	 * whose body is thousands of instructions of real computation and which
	 * happens to touch no new page is doing work, and its own timing
	 * condition will be satisfied at the honest rate soon enough; it is not
	 * something to hurry along. TSC_SPIN_GAP is far above any padding that
	 * is worth writing - the whole point of junk is that it is cheap - and
	 * far below a body that is actually computing something.
	 */
	int idle = e->last_new_page == e->tsc_last_page && gap < TSC_SPIN_GAP;

	e->tsc_last_page = e->last_new_page;
	if (idle) {
		/* Asked again having done nothing: a wait, not a measurement. */
		if (++e->tsc_spin > TSC_SPIN_AT) {
			uint32_t k = e->tsc_spin - TSC_SPIN_AT;

			e->tsc_skew += (uint64_t)TSC_SPIN_MIN <<
				       (k > 20u ? 20u : k);
		}
	} else {
		e->tsc_spin = 0;
	}
	e->tsc_last_insn = e->insn;
	return (e->insn + e->ff_insn) * TSC_PER_INSN + e->tsc_skew;
}

/* Nanoseconds, from the same clock. A tick is taken to be a nanosecond: the
 * unit is arbitrary and one that needs no conversion is one that cannot be
 * converted wrongly. */
static uint64_t tsc_ns(struct kgenome_emu *e)
{
	return kgenome_emu_tsc_read(e);
}

static uint64_t syscall_do(struct kgenome_emu *e, int *stop_out);
static uint64_t sysarg(const struct kgenome_emu *e, unsigned i);

uint64_t kgenome_emu_do_syscall(struct kgenome_emu *e, int *stop_out)
{
	struct kgenome_emu_syscall *s;
	uint64_t ret;

	s = &e->syslog[e->n_syslog % KGENOME_EMU_SYSLOG];
	/* The number AS THE GUEST GAVE IT, not the translated one: a reader of
	 * the log is looking at a 32-bit program and expects to see i386
	 * numbers. What it was translated to is the dispatcher's business. */
	s->nr     = e->bits == 32 ? (e->gpr[KGENOME_EMU_RAX] & 0xffffffffu)
				  : e->gpr[KGENOME_EMU_RAX];
	s->arg[0] = e->bits == 32 ? (e->gpr[KGENOME_EMU_RBX] & 0xffffffffu)
				  : e->gpr[KGENOME_EMU_RDI];
	s->arg[1] = e->bits == 32 ? (e->gpr[KGENOME_EMU_RCX] & 0xffffffffu)
				  : e->gpr[KGENOME_EMU_RSI];
	s->arg[2] = e->bits == 32 ? (e->gpr[KGENOME_EMU_RDX] & 0xffffffffu)
				  : e->gpr[KGENOME_EMU_RDX];
	s->arg[3] = sysarg(e, 0);
	s->arg[4] = sysarg(e, 1);
	s->arg[5] = sysarg(e, 2);
	ret = syscall_do(e, stop_out);
	s->ret = ret;
	e->n_syslog++;
	return ret;
}


unsigned kgenome_emu_syscall_log(const struct kgenome_emu *e,
			     struct kgenome_emu_syscall *out, unsigned n)
{
	unsigned k, got;
	uint32_t first;

	if (!e || !out)
		return 0;
	got = e->n_syslog < KGENOME_EMU_SYSLOG ? e->n_syslog : KGENOME_EMU_SYSLOG;
	first = e->n_syslog - got;
	if (got > n)
		got = n;
	for (k = 0; k < got; k++)
		out[k] = e->syslog[(first + k) % KGENOME_EMU_SYSLOG];
	return got;
}

unsigned kgenome_emu_unknown_syscalls(const struct kgenome_emu *e, uint32_t *out,
				  unsigned n)
{
	unsigned k, got;

	if (!e || !out)
		return 0;
	got = e->n_unksys < n ? e->n_unksys : n;
	for (k = 0; k < got; k++)
		out[k] = e->unksys[k];
	return got;
}

/* ---- syscalls -------------------------------------------------------------
 *
 * The whole environment, and it is this short on purpose. A packer stub wants
 * memory and then it wants to hand over; everything else it asks for can be
 * answered with a plausible number, because nothing downstream of this module
 * depends on the answer being true. What matters is that the stub keeps going
 * far enough to write its payload.
 *
 * An unknown call returns -ENOSYS rather than stopping. A stub that checks is
 * rare, and a stub that stops because we stopped it learns more than one that
 * gets a refusal it was already coded to survive.
 */
/*
 * EMU_SYS_ RATHER THAN SYS_, AND THE PREFIX IS NOT DECORATION.
 *
 * mingw-w64's <stdio.h> defines SYS_OPEN - an MSVC-era constant for how many
 * files a process may have open - so an unprefixed enumerator here collided
 * with a macro from a header nothing in this file includes on purpose, and the
 * entire Windows build stopped: this object is inside libkofeng.a, so the
 * failure took the library, both tools that link it, and every test, on x86_64
 * and ARM64 alike.
 *
 * The names are this file's alone - nothing outside it refers to one - so the
 * prefix costs nothing and removes the whole class of collision rather than the
 * one instance of it. A guard around the include order would have fixed today's
 * symbol and left the next one to be found by a build that breaks.
 */
enum {
	EMU_SYS_READ = 0, EMU_SYS_WRITE = 1, EMU_SYS_OPEN = 2, EMU_SYS_CLOSE = 3,
	EMU_SYS_FSTAT = 5, EMU_SYS_LSEEK = 8,
	EMU_SYS_MMAP = 9, EMU_SYS_MPROTECT = 10, EMU_SYS_MUNMAP = 11, EMU_SYS_BRK = 12,
	EMU_SYS_PREAD64 = 17, EMU_SYS_FTRUNCATE = 77, EMU_SYS_READLINK = 89,
	EMU_SYS_ARCH_PRCTL = 158, EMU_SYS_EXECVE = 59, EMU_SYS_EXIT = 60, EMU_SYS_EXIT_GROUP = 231,
	EMU_SYS_OPENAT = 257, EMU_SYS_NEWFSTATAT = 262, EMU_SYS_MEMFD_CREATE = 319,
	EMU_SYS_IOCTL = 16, EMU_SYS_SCHED_YIELD = 24, EMU_SYS_NANOSLEEP = 35,
	EMU_SYS_GETPID = 39, EMU_SYS_CLONE = 56, EMU_SYS_RT_SIGACTION = 13,
	EMU_SYS_RT_SIGPROCMASK = 14, EMU_SYS_SIGALTSTACK = 131, EMU_SYS_GETTID = 186,
	EMU_SYS_FUTEX = 202, EMU_SYS_SCHED_GETAFFINITY = 204, EMU_SYS_SET_TID_ADDRESS = 218,
	EMU_SYS_CLOCK_GETTIME = 228, EMU_SYS_SET_ROBUST_LIST = 273, EMU_SYS_PRLIMIT64 = 302,
	EMU_SYS_GETRANDOM = 318, EMU_SYS_MADVISE = 28, EMU_SYS_TGKILL = 234,
	EMU_SYS_RSEQ = 334, EMU_SYS_SIGRETURN = 15,
	EMU_SYS_GETTIMEOFDAY = 96, EMU_SYS_TIME = 201, EMU_SYS_GETCPU = 309,
	EMU_SYS_CLOCK_NANOSLEEP = 230, EMU_SYS_ALARM = 37, EMU_SYS_SETITIMER = 38,
	EMU_SYS_TIMER_CREATE = 222, EMU_SYS_TIMER_SETTIME = 223, EMU_SYS_PTRACE = 101,
	EMU_SYS_PAUSE = 34, EMU_SYS_SELECT = 23, EMU_SYS_POLL = 7, EMU_SYS_KILL = 62,
	/*
	 * WHAT A STUB ASKS BEFORE IT UNPACKS ANYTHING.
	 *
	 * None of these move a byte of payload, and that is exactly why they
	 * were worth adding: a packer asks who it is running as, on what
	 * kernel, with how much memory and from where, and -ENOSYS to any of
	 * them is an answer no real Linux ever gives. A stub that checks gets
	 * a louder signal from the refusal than it would from a slow machine -
	 * the same reasoning the sleep above is written under.
	 */
	EMU_SYS_UNAME = 63, EMU_SYS_GETUID = 102, EMU_SYS_GETGID = 104,
	EMU_SYS_GETEUID = 107, EMU_SYS_GETEGID = 108, EMU_SYS_GETPPID = 110,
	EMU_SYS_SYSINFO = 99, EMU_SYS_TIMES = 100, EMU_SYS_CLOCK_GETRES = 229,
	EMU_SYS_GETCWD = 79, EMU_SYS_PRCTL = 157, EMU_SYS_PERSONALITY = 135,
	EMU_SYS_GETRLIMIT = 97, EMU_SYS_SETRLIMIT = 160,
	EMU_SYS_ACCESS = 21, EMU_SYS_FACCESSAT = 269, EMU_SYS_FACCESSAT2 = 439,
	EMU_SYS_READLINKAT = 267, EMU_SYS_STAT = 4, EMU_SYS_LSTAT = 6,
	EMU_SYS_STATFS = 137, EMU_SYS_FSTATFS = 138,
	/*
	 * DESCRIPTORS, WHICH AN IN-MEMORY LOADER ACTUALLY USES.
	 *
	 * memfd_create, write the payload into it, dup it somewhere known,
	 * fexecve - that is the whole of a fileless ELF loader, and two of
	 * those four were already here. Every descriptor this emulator hands
	 * out names the same one file, so duplicating one is answering with a
	 * number; what matters is that the call succeeds.
	 */
	EMU_SYS_DUP = 32, EMU_SYS_DUP2 = 33, EMU_SYS_DUP3 = 292,
	EMU_SYS_FCNTL = 72, EMU_SYS_WRITEV = 20, EMU_SYS_READV = 19,
	EMU_SYS_PWRITE64 = 18, EMU_SYS_PIPE = 22, EMU_SYS_PIPE2 = 293,
	/* Growing a decompression buffer in place, which is what a stub does
	 * when it guessed the unpacked size too low. */
	EMU_SYS_MREMAP = 25
};

/*
 * A GUEST WORD, because half of these write a struct of longs and a long is
 * four bytes to a 32-bit guest.
 *
 * The stat above writes an amd64 struct whatever the guest is, which is safe
 * only because nothing reads past st_size. A struct of longs is different: a
 * 32-bit caller allocated half the bytes, so writing the 64-bit layout scribbles
 * past what it gave us - into its own heap, with the emulator as the corruptor.
 */
static unsigned gw(const struct kgenome_emu *e)
{
	return e->bits == 32 ? 4u : 8u;
}

/*
 * A stat, of the size the guest allocated for one.
 *
 * The only field anybody here reads is st_size - a stub asking how big it is -
 * and the rest stays zero. The SIZE matters though, and it used to not: this
 * wrote the 144-byte amd64 struct whatever the guest was, so a 32-bit caller
 * that allocated a 96-byte struct stat64 had forty-eight bytes of its own
 * memory overwritten by the emulator answering its question. st_size sits at a
 * different offset in each, which is the other half of the same fact.
 */
static uint64_t stat_out(struct kgenome_emu *e, uint64_t va);

/* Put one guest-sized word into a byte buffer and advance the cursor. */
static void gw_put(const struct kgenome_emu *e, uint8_t *b, unsigned *at, uint64_t v)
{
	if (gw(e) == 4u) {
		uint32_t w = (uint32_t)v;

		memcpy(b + *at, &w, 4);
		*at += 4u;
	} else {
		memcpy(b + *at, &v, 8);
		*at += 8u;
	}
}

static uint64_t stat_out(struct kgenome_emu *e, uint64_t va)
{
	uint8_t st[144];
	unsigned n   = e->bits == 32 ? 96u : 144u;
	unsigned off = e->bits == 32 ? 44u : 48u;

	memset(st, 0, sizeof st);
	memcpy(st + off, &e->self_n, 8);
	if (!kgenome_emu_mem_wr(e, va, st, n))
		return (uint64_t)-14;
	return 0;
}

/* The descriptor an emulated process gets for itself, and for anything else it
 * opens - there is only one file here and pretending otherwise would need a
 * filesystem nobody is going to write. */
#define EMU_SELF_FD  3

static uint64_t self_read(struct kgenome_emu *e, uint64_t va, uint64_t off,
			  uint64_t want)
{
	uint64_t n;

	if (!e->self || off >= e->self_n)
		return 0;
	n = e->self_n - off;
	if (n > want)
		n = want;
	if (!kgenome_emu_mem_wr(e, va, e->self + off, (unsigned)(n > 4096u ? 4096u : n)))
		return (uint64_t)-14;                           /* EFAULT */
	/* Written in page-sized bites so a large read cannot be half applied
	 * and then fail; the loop is here rather than in mem_wr because only
	 * this caller has a length the stub chose. */
	{
		uint64_t done = n > 4096u ? 4096u : n;

		while (done < n) {
			uint64_t chunk = n - done > 4096u ? 4096u : n - done;

			if (!kgenome_emu_mem_wr(e, va + done, e->self + off + done,
				    (unsigned)chunk))
				break;
			done += chunk;
		}
		return done;
	}
}

/* Where an mmap with no hint lands. High, and far from anything an ELF asks
 * for, so a stub that stores a returned pointer cannot be confused with one
 * that computed an address inside its own image. */
#define EMU_MMAP_BASE  0x00007f0000000000ull
/* A 32 bit guest has a 32 bit address space: its eax is all it reads back from mmap, so an arena above 4 GiB
 * would hand it 0 (or a truncated pointer). i386 Linux maps shared objects and anonymous memory just below
 * the stack (about 0xb7e00000 with the stack at 0xbffff000); this arena starts a little below that, grows
 * upward with a guard page between mappings like the 64 bit one, and stops short of the stack. */
#define EMU_LINUX_MMAP_BASE_32  0xb7000000ull
#define EMU_MMAP_LIMIT_32 0xf0000000ull

static uint64_t mmap_alloc(struct kgenome_emu *e, uint64_t len)
{
	uint64_t at;

	if (!e->mmap_next)
		e->mmap_next = e->bits == 32 ? EMU_LINUX_MMAP_BASE_32 : EMU_MMAP_BASE;
	at = e->mmap_next;
	if (e->bits == 32 && (at + len + KGENOME_EMU_PAGE > EMU_MMAP_LIMIT_32 || len > EMU_MMAP_LIMIT_32))
		return 0;                                   /* the 32 bit arena is full: ENOMEM */
	/* A guard page between mappings, so a stub that runs off the end of one faults here rather than
	 * silently scribbling on the next. */
	e->mmap_next += len + KGENOME_EMU_PAGE;
	return at;
}

/*
 * THE i386 SYSCALL NUMBERS THE STUBS HERE ACTUALLY USE, translated to the
 * amd64 ones the dispatcher below is written in.
 *
 * The two tables are unrelated - i386 write is 4 and amd64 write is 1 - so a
 * 32-bit stub run against the amd64 dispatcher asks for whatever happens to
 * share its number, which is worse than not running it at all: exit(1) on i386
 * is number 1, and amd64 number 1 is write. Translated rather than duplicated,
 * because what the syscalls DO is identical and only their numbering is not.
 *
 * A number with no row here returns -ENOSYS through the dispatcher's default,
 * the same as an unknown amd64 one. It is not the whole i386 table and does not
 * need to be.
 *
 * What it DOES need to be is as wide as the dispatcher, and it was not. This
 * table was written from the stubs measured when 32-bit mode was added, and the
 * dispatcher has grown since without it following: counted, the dispatcher
 * answered 52 numbers meaningfully and this table could reach 24 of them, so 28
 * considered answers sat unreachable from 32-bit code. Some of those matter to
 * what this interpreter is for - openat is what modern code calls instead of
 * open, fstat64 is how a stub finds its own size, clock_gettime is the timing
 * check the amd64 side deliberately answers - and a stub asking for one got
 * -ENOSYS while its 64-bit twin was served.
 *
 * The rows below are the ones whose numbers were read out of
 * asm/unistd_32.h rather than remembered. Anything still missing is missing on
 * purpose or has simply not been met yet; the gap to close was never "the whole
 * table", it was "everything this file already knows how to answer".
 */
static uint64_t i386_nr(uint64_t nr)
{
	switch (nr) {
	case 1:   return EMU_SYS_EXIT;
	case 2:   return EMU_SYS_GETPID;        /* fork; nothing here forks */
	/*
	 * THE ROWS ADDED WITH THE CALLS THEY REACH - see the note above about
	 * the two tables drifting apart. Numbers read out of asm/unistd_32.h.
	 *
	 * The *64 variants are DELIBERATELY ABSENT where their struct differs
	 * from the one the dispatcher writes: i386 stat64 and statfs64 carry
	 * 64-bit fields that a guest-word layout would fill wrongly, and a
	 * wrongly filled struct is worse than -ENOSYS because the guest
	 * believes it. The 16-bit id calls are absent for the same reason in
	 * reverse - nothing modern asks for them.
	 */
	/*
	 * 21, 22 AND 25 ARE NOT HERE, and used to be. i386 21 is mount, 22 umount and 25 stime, none of them
	 * access, pipe or getpid, which is what they were mapped to: a guest that mounted a file system was told
	 * it worked (access answered 0), one that called umount got a pipe, and stime answered with a pid. They are
	 * privileged calls an ordinary user is refused; unmapped, they are -ENOSYS and listed once like any other
	 * call the interpreter does not know (the amd64 numbers 21 and 22 are access and pipe, which is what
	 * the rows were copied from).
	 */
	case 33:  return EMU_SYS_ACCESS;
	case 41:  return EMU_SYS_DUP;
	case 42:  return EMU_SYS_PIPE;
	case 43:  return EMU_SYS_TIMES;
	case 55:  return EMU_SYS_FCNTL;
	case 63:  return EMU_SYS_DUP2;
	case 64:  return EMU_SYS_GETPPID;
	case 75:  return EMU_SYS_SETRLIMIT;
	case 76:  return EMU_SYS_GETRLIMIT;
	case 99:  return EMU_SYS_STATFS;
	case 100: return EMU_SYS_FSTATFS;
	case 116: return EMU_SYS_SYSINFO;
	case 122: return EMU_SYS_UNAME;
	case 136: return EMU_SYS_PERSONALITY;
	case 145: return EMU_SYS_READV;
	case 146: return EMU_SYS_WRITEV;
	case 163: return EMU_SYS_MREMAP;
	case 172: return EMU_SYS_PRCTL;
	case 181: return EMU_SYS_PWRITE64;
	case 183: return EMU_SYS_GETCWD;
	case 191: return EMU_SYS_GETRLIMIT;     /* ugetrlimit */
	case 199: return EMU_SYS_GETUID;
	case 200: return EMU_SYS_GETGID;
	case 201: return EMU_SYS_GETEUID;
	case 202: return EMU_SYS_GETEGID;
	case 221: return EMU_SYS_FCNTL;         /* fcntl64 */
	case 266: return EMU_SYS_CLOCK_GETRES;
	case 305: return EMU_SYS_READLINKAT;
	case 307: return EMU_SYS_FACCESSAT;
	case 330: return EMU_SYS_DUP3;
	case 331: return EMU_SYS_PIPE2;
	case 439: return EMU_SYS_FACCESSAT2;
	case 3:   return EMU_SYS_READ;
	case 4:   return EMU_SYS_WRITE;
	case 5:   return EMU_SYS_OPEN;
	case 6:   return EMU_SYS_CLOSE;
	case 11:  return EMU_SYS_EXECVE;
	case 13:  return EMU_SYS_TIME;
	case 19:  return EMU_SYS_LSEEK;
	case 20:  return EMU_SYS_GETPID;
	case 45:  return EMU_SYS_BRK;
	case 54:  return EMU_SYS_IOCTL;
	case 78:  return EMU_SYS_GETTIMEOFDAY;
	case 90:  return EMU_SYS_MMAP;          /* old_mmap, via a struct */
	case 91:  return EMU_SYS_MUNMAP;
	case 93:  return EMU_SYS_FTRUNCATE;
	case 125: return EMU_SYS_MPROTECT;
	case 85:  return EMU_SYS_READLINK;      /* /proc/self/exe             */
	case 120: return EMU_SYS_CLONE;
	case 158: return EMU_SYS_SCHED_YIELD;
	case 162: return EMU_SYS_NANOSLEEP;
	case 192: return EMU_SYS_MMAP;          /* mmap2 */
	case 174: return EMU_SYS_RT_SIGACTION;
	case 175: return EMU_SYS_RT_SIGPROCMASK;
	case 180: return EMU_SYS_PREAD64;
	case 197: return EMU_SYS_FSTAT;        /* fstat64; only st_size is read */
	case 219: return EMU_SYS_MADVISE;
	case 224: return EMU_SYS_GETTID;
	case 240: return EMU_SYS_FUTEX;
	case 242: return EMU_SYS_SCHED_GETAFFINITY;
	case 265: return EMU_SYS_CLOCK_GETTIME;
	case 267: return EMU_SYS_CLOCK_NANOSLEEP;
	case 270: return EMU_SYS_TGKILL;
	case 295: return EMU_SYS_OPENAT;
	case 26:  return EMU_SYS_PTRACE;
	case 252: return EMU_SYS_EXIT_GROUP;
	case 355: return EMU_SYS_GETRANDOM;
	case 356: return EMU_SYS_MEMFD_CREATE;
	default:  return nr | (1ull << 32);  /* no such i386 call: cannot collide */
	}
}



static uint64_t sysarg(const struct kgenome_emu *e, unsigned i)
{
	static const unsigned amd64[3] = { KGENOME_EMU_R10, KGENOME_EMU_R8, KGENOME_EMU_R9 };
	static const unsigned i386[3]  = { KGENOME_EMU_RSI, KGENOME_EMU_RDI, KGENOME_EMU_RBP };
	uint64_t v;

	if (i >= 3)
		return 0;
	v = e->gpr[e->bits == 32 ? i386[i] : amd64[i]];
	return e->bits == 32 ? (v & 0xffffffffu) : v;
}

/*
 * exit, execve and the memory calls.
 *
 * One arm of the dispatch in syscall_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t sys_proc_mem(struct kgenome_emu *e, uint64_t nr, uint64_t a0, uint64_t a1, int *stop_out, int *mine)
{
	*mine = 1;
	switch (nr) {
	case EMU_SYS_EXIT:
	case EMU_SYS_EXIT_GROUP:
		*stop_out = KGENOME_EMU_STOP_EXIT + 1;
		return 0;
	case EMU_SYS_EXECVE:
		/* The stub is done and is handing control to what it produced.
		 * Everything worth dumping has already been written. */
		*stop_out = KGENOME_EMU_STOP_HANDOFF + 1;
		return 0;
	case EMU_SYS_MMAP: {
		uint64_t len = (a1 + KGENOME_EMU_PAGE - 1u) & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		uint64_t prot = e->gpr[KGENOME_EMU_RDX];
		/*
		 * The descriptor is an int, and a caller that sets it with a
		 * 32-bit MOV leaves 0x00000000ffffffff in the register - which
		 * read as a valid fd, so every anonymous mapping was filled
		 * with the scanned file's bytes. A Go runtime allocated its
		 * heap that way and then followed a pointer made of file data.
		 * MAP_ANONYMOUS settles it regardless of what the fd looks
		 * like.
		 */
		int32_t  fd    = (int32_t)sysarg(e, 1);
		uint64_t flags = sysarg(e, 0);
		/* mmap2 (i386 192) counts its offset in 4096 byte pages; the amd64 call and old_mmap count bytes */
		uint64_t off = sysarg(e, 2) << ((e->bits == 32 && (e->gpr[KGENOME_EMU_RAX] & 0xffffffffu) == 192u) ? 12 : 0);
		uint64_t at;

		if (!len)
			return (uint64_t)-12;                   /* ENOMEM */
		if (a0) {
			at = a0 & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		} else {
			at = mmap_alloc(e, len);
			if (!at)
				return (uint64_t)-12;               /* ENOMEM */
		}
		/*
		 * PROT_NONE is a reservation and never becomes memory: nothing
		 * can read or write it while it stays that way, and Go reserves
		 * its heap in pieces far larger than this emulator would ever
		 * commit.
		 */
		if (!(prot & (KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X)))
			return at;
		/*
		 * A FILE-BACKED MAPPING IS HOW A STUB READS ITSELF.
		 *
		 * UPX never calls read(): it opens /proc/self/exe and maps the
		 * file, so the compressed image simply appears at an address.
		 * Answering that with anonymous zeroes hands the decompressor
		 * an empty buffer, and it fails without complaining - it walks
		 * an all-zero ELF header, finds e_phnum == 0, skips the whole
		 * load and returns a nonsense entry point. Every descriptor
		 * this emulator hands out refers to the scanned file, so any
		 * mapping of one is a window onto its bytes.
		 */
		if (!kgenome_emu_vma_add(e, at, len, off, (unsigned)prot & 7u,
			     fd >= 0 && !(flags & 0x20u) && e->self != NULL))
			return (uint64_t)-12;
		return at;
	}
	case EMU_SYS_MPROTECT:
		if (e->gpr[KGENOME_EMU_RDX] & KGENOME_EMU_X)
			kgenome_emu_snap_take(e, a0, a1);
		return 0;
	case EMU_SYS_MUNMAP:
	case EMU_SYS_BRK:
	case EMU_SYS_FTRUNCATE:
	case EMU_SYS_CLOSE:
		return 0;
	/*
	 * SERVICES A RUNTIME DEMANDS AND A PACKER NEVER USES.
	 *
	 * None of this changes a byte of what gets unpacked, but a Go runtime
	 * checks the return of each one and executes its own trap when the
	 * answer is -ENOSYS - so refusing them stops the emulation before the
	 * packer's own code runs at all. Each answers the least eventful thing
	 * that is true of this machine: one thread, one CPU, no signals, a
	 * clock that only moves forward.
	 */
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * the services a runtime demands and a packer never uses.
 *
 * One arm of the dispatch in syscall_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t sys_runtime(struct kgenome_emu *e, uint64_t nr, uint64_t a0, uint64_t a1, int *stop_out, int *mine)
{
	*mine = 1;
	switch (nr) {
	case EMU_SYS_FUTEX:
		/*
		 * A WAIT NOBODY WILL END.
		 *
		 * clone reports a thread id and nothing runs behind it, so the
		 * wake this caller wants can never arrive. Returning "woken"
		 * leaves it re-checking the word forever; writing the word a
		 * wakeup would have written was worse - measured, it let a Go
		 * scheduler run on past a handoff it had not really made, and
		 * it died on its own consistency check. So the wait is answered
		 * honestly, and a caller that keeps asking about the same
		 * address is recognised as stuck rather than humoured.
		 */
		if ((a1 & 0x7fu) == 0) {                    /* FUTEX_WAIT */
			if (a0 == e->futex_va && ++e->futex_spin > 64u) {
				*stop_out = KGENOME_EMU_STOP_STALLED + 1;
				return 0;
			}
			if (a0 != e->futex_va) {
				e->futex_va = a0;
				e->futex_spin = 0;
			}
		}
		return 0;
	/*
	 * A DELAY IS GRANTED IN FULL AND WAITED FOR NOT AT ALL.
	 *
	 * Sleeping is the cheapest anti-emulation trick there is: a stub that
	 * sleeps thirty seconds before unpacking costs an analyst nothing to
	 * run and costs an automated scan its entire time budget. Returning
	 * immediately and leaving the clock alone is the wrong fix, because the
	 * next thing such a stub does is ask what time it is - and a sleep that
	 * took no time is a louder signal than a slow machine. So the requested
	 * interval is added to the clock and the call returns at once: from
	 * inside, the sleep happened.
	 */
	case EMU_SYS_NANOSLEEP:
	case EMU_SYS_CLOCK_NANOSLEEP: {
		uint64_t req = (nr == EMU_SYS_NANOSLEEP) ? a0 : e->gpr[KGENOME_EMU_RDX];
		uint64_t ts[2], rem[2] = { 0, 0 };
		uint64_t back = (nr == EMU_SYS_NANOSLEEP) ? a1 : sysarg(e, 0);

		if (req && kgenome_emu_mem_rd(e, req, ts, sizeof ts))
			e->tsc_skew += ts[0] * 1000000000u + ts[1];
		/* Nothing was interrupted, so nothing remains. */
		if (back)
			kgenome_emu_mem_wr(e, back, rem, sizeof rem);
		return 0;
	}
	case EMU_SYS_PAUSE:
	case EMU_SYS_SELECT:
	case EMU_SYS_POLL:
		/*
		 * Waiting for something outside this process, which is a place
		 * nothing here can come from. Answered as a timeout - no
		 * descriptor is ready - so a caller that loops on it makes
		 * progress instead of blocking on an event that cannot arrive.
		 */
		return 0;
	case EMU_SYS_ALARM:
	case EMU_SYS_SETITIMER:
	case EMU_SYS_TIMER_CREATE:
	case EMU_SYS_TIMER_SETTIME:
		/* Armed, and it will never fire: signals are not delivered here.
		 * A watchdog that never goes off is the harmless direction. */
		return 0;
	case EMU_SYS_KILL:
		/* Including a stub signalling itself to die on a failed check.
		 * Refused rather than obeyed - the run ends on its own terms. */
		return (uint64_t)-1;                        /* EPERM */
	case EMU_SYS_PTRACE:
		/*
		 * PTRACE_TRACEME succeeds, which is what a process that is NOT
		 * already being debugged sees. The trick is to call it and
		 * treat failure as proof of a debugger; answering 0 says there
		 * is none.
		 */
		return 0;
	case EMU_SYS_MADVISE:
	case EMU_SYS_SCHED_YIELD:
	case EMU_SYS_SET_ROBUST_LIST:
	case EMU_SYS_SIGALTSTACK:
	case EMU_SYS_TGKILL:
	case EMU_SYS_RSEQ:
		return 0;
	case EMU_SYS_GETPID:
	case EMU_SYS_GETTID:
	case EMU_SYS_SET_TID_ADDRESS:
		return 1;
	case EMU_SYS_IOCTL:
		return (uint64_t)-25;                       /* ENOTTY: not a tty */
	case EMU_SYS_CLONE:
		/*
		 * The parent's half of a clone, and only that. This returns
		 * once, with a thread id, and the child never runs - there is
		 * one instruction pointer here. Refusing instead was worse: a
		 * Go runtime treats a failed thread creation as fatal and quits
		 * before reaching the packer's code. A child that is never
		 * scheduled is a thread that has not got started yet, which is
		 * a state every threaded program is written to tolerate.
		 */
		e->next_tid++;
		return e->next_tid;
	case EMU_SYS_RT_SIGACTION:
	case EMU_SYS_RT_SIGPROCMASK: {
		/* The old value, if asked for, is "nothing was set". */
		uint64_t old = (nr == EMU_SYS_RT_SIGACTION) ? e->gpr[KGENOME_EMU_RDX] : a1;
		uint8_t z[152];

		if (old) {
			memset(z, 0, sizeof z);
			kgenome_emu_mem_wr(e, old, z, nr == EMU_SYS_RT_SIGACTION ? 32u : 8u);
		}
		return 0;
	}
	case EMU_SYS_SCHED_GETAFFINITY: {
		uint64_t mask = 1;                          /* one CPU, cpu 0 */

		if (a1 < 8 || !kgenome_emu_mem_wr(e, e->gpr[KGENOME_EMU_RDX], &mask, 8))
			return (uint64_t)-22;               /* EINVAL */
		return 8;
	}
	case EMU_SYS_GETTIMEOFDAY: {
		uint64_t now = tsc_ns(e), tv[2];

		tv[0] = now / 1000000000u;
		tv[1] = (now % 1000000000u) / 1000u;
		if (a0 && !kgenome_emu_mem_wr(e, a0, tv, sizeof tv))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_TIME: {
		uint64_t now = tsc_ns(e) / 1000000000u;

		if (a0 && !kgenome_emu_mem_wr(e, a0, &now, 8))
			return (uint64_t)-14;
		return now;
	}
	case EMU_SYS_GETCPU: {
		uint64_t z = 0;

		if (a0 && !kgenome_emu_mem_wr(e, a0, &z, 4))
			return (uint64_t)-14;
		if (a1 && !kgenome_emu_mem_wr(e, a1, &z, 4))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_CLOCK_GETTIME: {
		/* Same clock RDTSC reports, in nanoseconds. */
		uint64_t now = tsc_ns(e), ts[2];

		ts[0] = now / 1000000000u;
		ts[1] = now % 1000000000u;
		if (!kgenome_emu_mem_wr(e, a1, ts, sizeof ts))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_PRLIMIT64: {
		/* 8 MB of stack, and as many descriptors as anyone asks for. */
		uint64_t lim[2] = { 8u * 1024u * 1024u, ~(uint64_t)0 };

		if (sysarg(e, 0) &&
		    !kgenome_emu_mem_wr(e, sysarg(e, 0), lim, sizeof lim))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_GETRANDOM: {
		/*
		 * Deterministic on purpose. A scan that returns a different
		 * answer each run cannot be tested, and nothing that unpacks a
		 * payload takes its key from here - the key travels with the
		 * file.
		 */
		uint64_t n = a1, k;
		uint8_t b[256];

		/*
		 * Bounded, because this loop is inside ONE guest instruction
		 * and the instruction budget therefore does not see it. A guest
		 * asking for a terabyte of randomness would spin here with the
		 * budget untouched. The real call is capped too, so a short
		 * return is an answer a caller is written to handle.
		 */
		if (n > (1u << 20))
			n = 1u << 20;
		for (k = 0; k < n; k += sizeof b) {
			uint64_t c = n - k < sizeof b ? n - k : sizeof b, j;

			for (j = 0; j < c; j++)
				b[j] = (uint8_t)((k + j) * 37u + 11u);
			if (!kgenome_emu_mem_wr(e, a0 + k, b, (unsigned)c))
				return (uint64_t)-14;
		}
		return n;
	}
	case EMU_SYS_ARCH_PRCTL:
		/* ARCH_SET_FS / ARCH_SET_GS. The two GET codes report where the
		 * emulator put them, so a runtime that reads its own thread
		 * pointer back gets what it wrote. */
		if (a0 == 0x1002)      { e->fs_base = a1; return 0; }
		if (a0 == 0x1001)      { e->gs_base = a1; return 0; }
		if (a0 == 0x1003 || a0 == 0x1004) {
			uint64_t v = (a0 == 0x1003) ? e->fs_base : e->gs_base;

			if (!kgenome_emu_mem_wr(e, a1, &v, 8))
				return (uint64_t)-14;
			return 0;
		}
		return (uint64_t)-22;                       /* EINVAL */
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * opening, access, stat and the names of things.
 *
 * One arm of the dispatch in syscall_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t sys_files(struct kgenome_emu *e, uint64_t nr, uint64_t a0, uint64_t a1, int *mine)
{
	*mine = 1;
	switch (nr) {
	case EMU_SYS_MEMFD_CREATE:
	case EMU_SYS_OPEN:
	case EMU_SYS_OPENAT:
		return EMU_SELF_FD;
	/*
	 * EVERY PATH EXISTS AND IS READABLE, which is the same lie open()
	 * above already tells and is the consistent one. A stub checking for
	 * /proc/self/status before it will run gets the answer a real machine
	 * gives; -ENOENT here and a successful open two lines later would be
	 * an inconsistency worth noticing.
	 */
	case EMU_SYS_ACCESS:
	case EMU_SYS_FACCESSAT:
	case EMU_SYS_FACCESSAT2:
		return 0;
	case EMU_SYS_STAT:
	case EMU_SYS_LSTAT:
		return stat_out(e, a1);
	case EMU_SYS_STATFS:
	case EMU_SYS_FSTATFS: {
		/*
		 * AN ORDINARY DISK, and the choice of magic is the whole point.
		 *
		 * A sandbox check does not ask whether the filesystem works, it
		 * asks what KIND it is: overlayfs (0x794c7630) says container,
		 * tmpfs (0x01021994) says the file was dropped into RAM by
		 * something. ext4 says a machine somebody uses.
		 */
		uint8_t sf[120];
		unsigned at = 0;

		memset(sf, 0, sizeof sf);
		gw_put(e, sf, &at, 0xEF53u);          /* f_type: ext2/3/4    */
		gw_put(e, sf, &at, 4096u);            /* f_bsize             */
		gw_put(e, sf, &at, 26214400u);        /* f_blocks: 100 GB    */
		gw_put(e, sf, &at, 13107200u);        /* f_bfree:  half free */
		gw_put(e, sf, &at, 13107200u);        /* f_bavail            */
		gw_put(e, sf, &at, 6553600u);         /* f_files             */
		gw_put(e, sf, &at, 6000000u);         /* f_ffree             */
		/* statfs(path, buf) and fstatfs(fd, buf): the buffer is the SECOND argument in both ABIs (rsi on
		 * amd64, ecx on i386); reading it from RSI answered a 32 bit guest into whatever esi held. */
		if (!kgenome_emu_mem_wr(e, a1, sf, at))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_READLINKAT: {
		/* readlink's answer, one argument along. */
		static const char path[] = "/proc/self/exe";
		uint64_t n = sizeof path - 1u, room = sysarg(e, 0);

		if (n > room)
			n = room;
		if (!kgenome_emu_mem_wr(e, e->gpr[KGENOME_EMU_RDX], path, (unsigned)n))
			return (uint64_t)-14;
		return n;
	}
	case EMU_SYS_GETCWD: {
		static const char cwd[] = "/tmp";
		uint64_t n = sizeof cwd;              /* the NUL is included */

		if (n > a1)
			return (uint64_t)-34;           /* ERANGE */
		if (!kgenome_emu_mem_wr(e, a0, cwd, (unsigned)n))
			return (uint64_t)-14;
		return n;
	}
	case EMU_SYS_UNAME: {
		/*
		 * SIX FIXED-WIDTH NAMES, and a plausible one in each.
		 *
		 * A stub reads `machine` to pick a code path and `release` to
		 * decide whether a syscall it wants exists. A kernel version
		 * old enough to lack memfd_create would send a loader down a
		 * path this emulator then has to carry, so the release named
		 * here is recent enough that the modern path is the one taken.
		 */
		char u[6 * 65];
		unsigned i;
		static const char *const fld[6] = {
			"Linux", "localhost", "6.1.0-18-amd64",
			"#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1",
			NULL, ""
		};

		memset(u, 0, sizeof u);
		for (i = 0; i < 6u; i++) {
			const char *t = fld[i];

			if (i == 4u)
				t = e->bits == 32 ? "i686" : "x86_64";
			memcpy(u + i * 65u, t, strlen(t));
		}
		if (!kgenome_emu_mem_wr(e, a0, u, sizeof u))
			return (uint64_t)-14;
		return 0;
	}
	/*
	 * ROOT-LESS AND ORDINARY. uid 1000 rather than 0: a stub that only
	 * unpacks when it is root would otherwise take a path this emulator
	 * cannot follow to anywhere useful, and a stub that refuses to run AS
	 * root - malware avoiding an analyst's box - would refuse.
	 */
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * identity, system information, limits and descriptors.
 *
 * One arm of the dispatch in syscall_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t sys_ident(struct kgenome_emu *e, uint64_t nr, uint64_t a0, uint64_t a1, int *mine)
{
	*mine = 1;
	switch (nr) {
	case EMU_SYS_GETUID:
	case EMU_SYS_GETEUID:  return 1000;
	case EMU_SYS_GETGID:
	case EMU_SYS_GETEGID:  return 1000;
	case EMU_SYS_GETPPID:  return 1;
	case EMU_SYS_SYSINFO: {
		/*
		 * A MACHINE SOMEBODY USES, measured against what a sandbox
		 * check looks for: too little RAM and too short an uptime are
		 * the two it keys on. Eight gigabytes and eleven days.
		 */
		uint8_t si[128];
		unsigned at = 0;
		/*
		 * A 32 bit guest's unsigned long cannot hold 8 GiB: written as it was, totalram was 0 - a machine with
		 * no memory, the very tell this call is answered to avoid. The kernel's own answer (sys_sysinfo) when
		 * RAM and swap together overflow the word is to count in mem_unit, a page: so does this.
		 */
		uint64_t unit = gw(e) == 4u ? 4096u : 1u;

		memset(si, 0, sizeof si);
		gw_put(e, si, &at, 987654u);                  /* uptime, s    */
		gw_put(e, si, &at, 12000u);                   /* loads[0]     */
		gw_put(e, si, &at, 14000u);
		gw_put(e, si, &at, 16000u);
		gw_put(e, si, &at, 8ull * 1024 * 1024 * 1024 / unit);/* totalram     */
		gw_put(e, si, &at, 3ull * 1024 * 1024 * 1024 / unit);/* freeram      */
		gw_put(e, si, &at, 0);                        /* sharedram    */
		gw_put(e, si, &at, 512ull * 1024 * 1024 / unit);     /* bufferram    */
		gw_put(e, si, &at, 2ull * 1024 * 1024 * 1024 / unit);/* totalswap    */
		gw_put(e, si, &at, 2ull * 1024 * 1024 * 1024 / unit);/* freeswap     */
		si[at++] = 214; si[at++] = 0;                 /* procs        */
		at += 2u;                                     /* pad          */
		if (gw(e) == 8u)
			at += 4u;                             /* alignment    */
		gw_put(e, si, &at, 0);                        /* totalhigh    */
		gw_put(e, si, &at, 0);                        /* freehigh     */
		at += 4u;                                     /* mem_unit     */
		si[at - 4u] = (uint8_t)(unit & 0xffu);
		si[at - 3u] = (uint8_t)(unit >> 8);
		if (!kgenome_emu_mem_wr(e, a0, si, at))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_TIMES: {
		/* Four clock_t of CPU time, from the same clock as everything
		 * else. 100 ticks a second is what _SC_CLK_TCK is everywhere
		 * this matters. */
		uint64_t t = tsc_ns(e) / 10000000u;
		uint8_t tms[32];
		unsigned at = 0;

		memset(tms, 0, sizeof tms);
		gw_put(e, tms, &at, t);
		gw_put(e, tms, &at, t / 4u);
		gw_put(e, tms, &at, 0);
		gw_put(e, tms, &at, 0);
		if (a0 && !kgenome_emu_mem_wr(e, a0, tms, at))
			return (uint64_t)-14;
		return t;
	}
	case EMU_SYS_CLOCK_GETRES: {
		/* A nanosecond, which is the unit the clock here counts in. */
		uint8_t ts[16];
		unsigned at = 0;

		gw_put(e, ts, &at, 0);
		gw_put(e, ts, &at, 1);
		if (a1 && !kgenome_emu_mem_wr(e, a1, ts, at))
			return (uint64_t)-14;
		return 0;
	}
	case EMU_SYS_PRCTL: {
		/*
		 * PR_GET_DUMPABLE answers 1 - a process being traced by
		 * somebody would read 0, and that is the check. Everything
		 * else is a setter and succeeds.
		 */
		if (a0 == 3u) {                         /* PR_GET_DUMPABLE */
			uint32_t one = 1u;

			if (a1 && !kgenome_emu_mem_wr(e, a1, &one, 4))
				return (uint64_t)-14;
			return 1;
		}
		return 0;
	}
	case EMU_SYS_PERSONALITY:
		/* The previous personality, which was the ordinary one. Some
		 * packers turn ASLR off before mapping; nothing here moves. */
		return 0;
	case EMU_SYS_GETRLIMIT:
	case EMU_SYS_SETRLIMIT: {
		uint8_t lim[16];
		unsigned at = 0;

		if (nr == EMU_SYS_SETRLIMIT)
			return 0;
		gw_put(e, lim, &at, 8ull * 1024 * 1024);      /* soft: stack */
		gw_put(e, lim, &at, ~(uint64_t)0);            /* hard        */
		if (a1 && !kgenome_emu_mem_wr(e, a1, lim, at))
			return (uint64_t)-14;
		return 0;
	}
	/*
	 * There is one file and one descriptor for it, so a duplicate is a
	 * number. dup2 and dup3 are told which number to answer with and are
	 * obliged to; dup picks one that is not already spoken for.
	 */
	case EMU_SYS_DUP:   return EMU_SELF_FD;
	case EMU_SYS_DUP2:
	case EMU_SYS_DUP3:  return a1;
	case EMU_SYS_FCNTL:
		switch (a1) {
		case 0:  return EMU_SELF_FD;            /* F_DUPFD      */
		case 1:  return 0;                      /* F_GETFD      */
		case 3:  return 0;                      /* F_GETFL: RDONLY */
		default: return 0;                      /* every setter */
		}
	case EMU_SYS_PIPE:
	case EMU_SYS_PIPE2: {
		/* Both ends name the same file, like every other descriptor
		 * here. A stub that pipes to itself makes progress; one that
		 * expects to read back what it wrote does not, and neither
		 * outcome unpacks anything. */
		uint32_t fds[2] = { EMU_SELF_FD, EMU_SELF_FD };

		if (!kgenome_emu_mem_wr(e, a0, fds, sizeof fds))
			return (uint64_t)-14;
		return 0;
	}
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * vectored and positioned I/O, the file offset, read and write.
 *
 * One arm of the dispatch in syscall_do, moved out so the dispatch stays readable.
 * Sets *mine to 0 for an id that is not one of its own.
 */
static uint64_t sys_io(struct kgenome_emu *e, uint64_t nr, uint64_t a0, uint64_t a1, int *stop_out, int *mine)
{
	*mine = 1;
	switch (nr) {
	case EMU_SYS_PWRITE64:
		return e->gpr[KGENOME_EMU_RDX];             /* wrote it all */
	case EMU_SYS_WRITEV:
	case EMU_SYS_READV: {
		/*
		 * A VECTOR OF (base, len) IN GUEST WORDS. glibc writes through
		 * writev rather than write, so a stub that prints anything at
		 * all arrives here and not at WRITE - and answering -ENOSYS
		 * made the common case of "it told us what it was doing" into
		 * a stop.
		 */
		uint64_t vec = a1, n = e->gpr[KGENOME_EMU_RDX], i, done = 0;
		unsigned w = gw(e);

		if (n > 1024u)
			n = 1024u;
		for (i = 0; i < n; i++) {
			uint8_t ent[16];
			uint64_t base = 0, len = 0;

			if (!kgenome_emu_mem_rd(e, vec + i * 2u * w, ent, 2u * w))
				break;
			if (w == 4u) {
				uint32_t b32, l32;

				memcpy(&b32, ent, 4);
				memcpy(&l32, ent + 4, 4);
				base = b32; len = l32;
			} else {
				memcpy(&base, ent, 8);
				memcpy(&len, ent + 8, 8);
			}
			if (nr == EMU_SYS_WRITEV) {
				/* Kept, up to what the say buffer holds, the
				 * same way WRITE keeps it. */
				if (a0 <= 2u && e->n_say < KGENOME_EMU_SAY) {
					uint64_t room = KGENOME_EMU_SAY - e->n_say;

					if (len < room)
						room = len;
					if (kgenome_emu_mem_rd(e, base,
						   e->say + e->n_say,
						   (unsigned)room))
						e->n_say += (uint32_t)room;
				}
				done += len;
			} else {
				/* self_read(e, va, off, len): the position is the OFFSET and the vector's length the
				 * count (the arguments were in the other order, so nothing was ever read) */
				uint64_t got = self_read(e, base, e->self_pos, len);

				if (got > len)                      /* -EFAULT: the bytes before it were read */
					return done ? done : got;
				e->self_pos += got;
				done += got;
				if (got < len)
					break;
			}
		}
		return done;
	}
	case EMU_SYS_MREMAP: {
		/*
		 * GROW BY MOVING, because nothing here ever gives memory back -
		 * see MUNMAP, which is a no-op. So the old mapping stays where
		 * it is and the new one is somewhere else with the bytes copied
		 * across, which is what MREMAP_MAYMOVE promises anyway.
		 *
		 * Without that flag a kernel would try to extend in place and
		 * answer -ENOMEM when it cannot; the guest handles that, and
		 * pretending to succeed would hand it an address it believes
		 * is contiguous with something it is not.
		 */
		uint64_t old_len = (a1 + KGENOME_EMU_PAGE - 1u) &
				   ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		uint64_t new_len = (e->gpr[KGENOME_EMU_RDX] + KGENOME_EMU_PAGE - 1u) &
				   ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		uint64_t flags = sysarg(e, 0), at, done;

		if (!new_len)
			return (uint64_t)-22;                   /* EINVAL */
		if (new_len <= old_len)
			return a0;                    /* shrink in place */
		if (!(flags & 1u))
			return (uint64_t)-12;                   /* ENOMEM */
		at = mmap_alloc(e, new_len);
		if (!at)
			return (uint64_t)-12;
		if (!kgenome_emu_vma_add(e, at, new_len, 0,
			     KGENOME_EMU_R | KGENOME_EMU_W, 0))
			return (uint64_t)-12;
		for (done = 0; done < old_len; ) {
			uint8_t page[KGENOME_EMU_PAGE];
			uint64_t chunk = old_len - done;

			if (chunk > KGENOME_EMU_PAGE)
				chunk = KGENOME_EMU_PAGE;
			if (!kgenome_emu_mem_rd(e, a0 + done, page, (unsigned)chunk))
				break;
			if (!kgenome_emu_mem_wr(e, at + done, page, (unsigned)chunk))
				break;
			done += chunk;
		}
		return at;
	}
	case EMU_SYS_READLINK: {
		/* Whatever was asked about is this process. The path only has to
		 * be openable, and every open here answers with the same file. */
		static const char path[] = "/proc/self/exe";
		uint64_t n = sizeof path - 1u;

		if (n > e->gpr[KGENOME_EMU_RDX])
			n = e->gpr[KGENOME_EMU_RDX];
		if (!kgenome_emu_mem_wr(e, a1, path, (unsigned)n))
			return (uint64_t)-14;
		return n;
	}
	case EMU_SYS_LSEEK: {
		uint64_t whence = e->gpr[KGENOME_EMU_RDX];

		if (whence == 0)      e->self_pos = a1;
		else if (whence == 1) e->self_pos += a1;
		else                  e->self_pos = e->self_n + a1;
		return e->self_pos;
	}
	case EMU_SYS_PREAD64:
		return self_read(e, a1, sysarg(e, 0), e->gpr[KGENOME_EMU_RDX]);
	case EMU_SYS_FSTAT:
	case EMU_SYS_NEWFSTATAT: {
		uint64_t at = (nr == EMU_SYS_FSTAT) ? a1 : e->gpr[KGENOME_EMU_RDX];

		return stat_out(e, at);
	}
	case EMU_SYS_WRITE: {
		uint64_t n = e->gpr[KGENOME_EMU_RDX];

		if (a0 <= 2 && e->n_say < KGENOME_EMU_SAY) {
			uint64_t room = KGENOME_EMU_SAY - e->n_say;

			if (n < room)
				room = n;
			if (kgenome_emu_mem_rd(e, a1, e->say + e->n_say, (unsigned)room))
				e->n_say += (uint32_t)room;
		}
		return n;                                       /* wrote it all */
	}
	case EMU_SYS_READ: {
		uint64_t got;

		/*
		 * READING STANDARD INPUT IS END OF FILE, and answering it any
		 * other way costs an entire budget.
		 *
		 * Every open here hands back EMU_SELF_FD, so a descriptor of 0,
		 * 1 or 2 was never opened: it is the terminal the process
		 * inherited, and there is no terminal. Serving those reads from
		 * the scanned file - which is what ignoring the descriptor did -
		 * feeds a stub the packed image one byte at a time and never
		 * reaches an end, so a stub that waits for input waits forever.
		 *
		 * Measured on midgetpack, which asks for a password: 61 reads of
		 * stdin answered with file bytes, then four million instructions
		 * of nothing, 0.47 s per object and 75 s over 200 of them, with
		 * no payload recovered because there was never a password to
		 * recover it with. Answering 0 ends the prompt on its first
		 * read, the stub gives up the way it would on a closed pipe, and
		 * the run stops in milliseconds.
		 *
		 * EOF rather than EAGAIN or EIO: a closed input is an ordinary
		 * thing a program is written to handle, and an error is not.
		 *
		 * AND A PROMPT THAT IGNORES EOF ASKS FOREVER, which is the same
		 * shape as the futex wait above and is answered the same way.
		 * midgetpack's prompt does not check the return at all - it
		 * loops until it sees a newline - so end-of-file alone does not
		 * end it; measured, it still spent the whole budget. A caller
		 * that has been told the input is over and asks again has
		 * stopped making progress, and after a handful of those the run
		 * is stuck rather than working. The handful is what separates it
		 * from a program that legitimately probes stdin once or twice
		 * before giving up on its own.
		 */
		if ((int64_t)a0 >= 0 && a0 <= 2) {
			if (++e->stdin_eof > 8u) {
				*stop_out = KGENOME_EMU_STOP_STALLED + 1;
				return 0;
			}
			return 0;
		}
		e->stdin_eof = 0;
		got = self_read(e, a1, e->self_pos, e->gpr[KGENOME_EMU_RDX]);
		if ((int64_t)got > 0)
			e->self_pos += got;
		return got;
	}
	default:
		*mine = 0;
		return 0;
	}
}

/*
 * i386 old_mmap (90): ONE argument, a pointer to six 32 bit words (addr, len, prot, flags, fd, offset in bytes)
 * - the call glibc made before mmap2. Served by laying the words out as mmap2 reads its registers and
 * running that, then putting the guest's own registers back: nothing else is touched. An unreadable block is -EFAULT.
 */
static uint64_t old_mmap(struct kgenome_emu *e, int *stop_out)
{
	static const unsigned reg[6] = { KGENOME_EMU_RBX, KGENOME_EMU_RCX, KGENOME_EMU_RDX,
					 KGENOME_EMU_RSI, KGENOME_EMU_RDI, KGENOME_EMU_RBP };
	uint32_t w[6];
	uint64_t save[6], rax = e->gpr[KGENOME_EMU_RAX], r;
	unsigned k;

	if (!kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RBX] & 0xffffffffu, w, sizeof w))
		return (uint64_t)-14;                           /* EFAULT */
	for (k = 0; k < 6u; k++) {
		save[k] = e->gpr[reg[k]];
		e->gpr[reg[k]] = w[k];
	}
	e->gpr[KGENOME_EMU_RBP] = w[5] >> 12;                   /* mmap2's unit is a page */
	e->gpr[KGENOME_EMU_RAX] = 192u;
	r = syscall_do(e, stop_out);
	for (k = 0; k < 6u; k++)
		e->gpr[reg[k]] = save[k];
	e->gpr[KGENOME_EMU_RAX] = rax;
	return r;
}

static uint64_t syscall_do(struct kgenome_emu *e, int *stop_out)
{
	if (e->bits == 32 && (e->gpr[KGENOME_EMU_RAX] & 0xffffffffu) == 90u)
		return old_mmap(e, stop_out);

	/*
	 * i386 passes the number in eax and the arguments in ebx, ecx, edx,
	 * esi, edi, ebp - a different register for every one of them than amd64
	 * uses. Read here rather than by moving the guest's registers about,
	 * because the guest is entitled to find them unchanged when the call
	 * returns.
	 */
	uint64_t nr = e->bits == 32 ? i386_nr(e->gpr[KGENOME_EMU_RAX] & 0xffffffffu)
				    : e->gpr[KGENOME_EMU_RAX];
	uint64_t a0 = e->bits == 32 ? (e->gpr[KGENOME_EMU_RBX] & 0xffffffffu)
				    : e->gpr[KGENOME_EMU_RDI];
	uint64_t a1 = e->bits == 32 ? (e->gpr[KGENOME_EMU_RCX] & 0xffffffffu)
				    : e->gpr[KGENOME_EMU_RSI];

	/*
	 * The Windows ids first, and against the RAW register rather than `nr`:
	 * a 32-bit guest's number goes through i386_nr, which maps i386 numbers
	 * onto amd64 ones and would turn one of these into something else
	 * entirely. See the Windows environment above for why the range is safe.
	 */
	{
		uint32_t raw = (uint32_t)(e->gpr[KGENOME_EMU_RAX] & 0xffffffffu);

		if (raw >= KGENOME_EMU_WIN_API_BASE &&
		    raw < KGENOME_EMU_WIN_API_BASE + KGENOME_EMU_WIN_API_COUNT + kgenome_emu_win_export_total())
			{
				unsigned wid = raw - KGENOME_EMU_WIN_API_BASE;
				uint64_t r;

				if (wid >= KGENOME_EMU_WIN_API_COUNT) {
					/* A name with a stub and no model: answer 0, and say so. On i386 a count nobody knows
					 * leaves the callee's cleanup a guess. */
					*stop_out = 0;
					e->unmodelled++;
					if (e->bits == 32 && kgenome_emu_win_export_argc(wid - KGENOME_EMU_WIN_API_COUNT) ==
								KGENOME_EMU_WIN_ARGC_UNKNOWN)
						e->unmodelled_guess++;
					return kgenome_emu_win_export_answer(wid - KGENOME_EMU_WIN_API_COUNT);
				}
				r = kgenome_emu_winapi_do(e, wid, stop_out);

				kgenome_emu_win_event_note(e, wid, r);

				/* The ANSWER, not just the question. A call
				 * that was made and a call that was answered
				 * wrongly look the same from the entry line,
				 * and the second is what sends a program down
				 * its failure path. */
				kgenome_emu_win_trace(e, kgenome_emu_win_api_name(wid),
					  "= ", r);
				return r;
			}
	}

	*stop_out = 0;
	{
		int mine;
		uint64_t r;

		r = sys_proc_mem(e, nr, a0, a1, stop_out, &mine);
		if (mine)
			return r;
		r = sys_runtime(e, nr, a0, a1, stop_out, &mine);
		if (mine)
			return r;
		r = sys_files(e, nr, a0, a1, &mine);
		if (mine)
			return r;
		r = sys_ident(e, nr, a0, a1, &mine);
		if (mine)
			return r;
		r = sys_io(e, nr, a0, a1, stop_out, &mine);
		if (mine)
			return r;
	}
	if (e->n_unksys < KGENOME_EMU_UNKSYS) {
		uint32_t i;

		for (i = 0; i < e->n_unksys; i++)
			if (e->unksys[i] == (uint32_t)nr)
				break;
		if (i == e->n_unksys)
			e->unksys[e->n_unksys++] = (uint32_t)nr;
	}
	return (uint64_t)-38;                           /* ENOSYS */
}
