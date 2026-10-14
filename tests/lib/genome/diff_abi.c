/*
 * diff_abi - the same system call in a 32 bit guest and a 64 bit guest, side by side.
 *
 * The syscall dispatcher is written once, in amd64 numbers and register order, and a 32 bit guest reaches it through
 * a translation table and the i386 argument registers (ebx ecx edx esi edi ebp). What differs between the two
 * guests is not the idea of a call but its LAYOUT, and each difference below was either a defect found by looking
 * (statfs read its buffer from esi, mmap handed a 32 bit guest an address above 4 GiB, readv swapped its offset and
 * its length) or is the next one waiting. Each case runs the logical call in both guests with the arguments the
 * ABI lays out, and compares what the guest can see:
 *
 *   RETURN    a result is the full word in a 64 bit guest and 32 bits in the other; -errno is the same errno in
 *             both widths (0xfffffff2 and 0xfffffffffffffff2 are both -EFAULT)
 *   MMAP      a 32 bit guest's address fits its register, is page aligned, is zero and writable to the end of
 *             the rounded length, and the next mapping lies elsewhere; length zero is -ENOMEM in both; the
 *             old_mmap form takes a pointer to its six arguments; a descriptor-backed map is the scanned file
 *   STRUCTS   struct stat (96 bytes with st_size at 44 for stat64, 144 with st_size at 48), statfs (4 byte fields
 *             and 8 byte fields: the same f_type, f_bsize and block counts), sysinfo, rlimit (RLIM_INFINITY is 32 and 64
 *             bits of ones), timespec and timeval (two words), iovec (two words per entry): the values, not the
 *             bytes, are equal, and nothing is written past the struct the guest allocated
 *   STRINGS   uname's six names, getcwd, readlink, getrandom: the same bytes in both
 *   INT 0x80  a 64 bit guest may still use the i386 convention, with the i386 numbers
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


/* the two ABIs' numbers for one logical call */
struct nr { uint64_t a64, a32; };

static const struct nr N_MMAP = { 9, 192 }, N_OLDMMAP = { 9, 90 }, N_FSTAT = { 5, 197 }, N_STATFS = { 137, 99 }, N_FSTATFS = { 138, 100 },
		       N_SYSINFO = { 99, 116 }, N_GETRLIMIT = { 97, 76 }, N_UGETRLIMIT = { 97, 191 }, N_CLOCKGT = { 228, 265 },
		       N_GETTOD = { 96, 78 }, N_TIME = { 201, 13 }, N_NANOSLP = { 35, 162 }, N_UNAME = { 63, 122 }, N_GETCWD = { 79, 183 },
		       N_READLINK = { 89, 85 }, N_GETRANDOM = { 318, 355 }, N_READV = { 19, 145 }, N_WRITEV = { 20, 146 }, N_LSEEK = { 8, 19 },
		       N_PIPE = { 22, 42 }, N_GETPID = { 39, 20 }, N_GETUID = { 102, 199 },
		       N_OPEN = { 2, 5 };

static uint64_t SYS(struct nr n, unsigned bits)
{
	return bits == 32 ? n.a32 : n.a64;
}

/* word i of a struct of guest-width words */
static uint64_t word(struct kgenome_emu *e, unsigned bits, uint64_t va, unsigned i)
{
	return get(e, va + (uint64_t)i * (bits / 8u), bits / 8u);
}

static void t_return_width(void)
{
	unsigned bits;

	for (bits = 32; bits <= 64; bits += 32) {
		struct kgenome_emu *e = mk(bits);
		struct res r;

		if (!e) {
			CK(0, "emulator");
			return;
		}
		r = sys(e, bits, SYS(N_FSTAT, bits), 3, 0x7e000000, 0, 0, 0, 0);
		CK(r.ret == errv(bits, 14), "%u bit: fstat into unmapped memory is -EFAULT in the guest's own width (%#llx)", bits, (unsigned long long)r.ret);
		r = sys(e, bits, SYS(N_STATFS, bits), DATA, 0x7e000000, 0, 0, 0, 0);
		CK(r.ret == errv(bits, 14), "%u bit: statfs into unmapped memory is -EFAULT (%#llx)", bits, (unsigned long long)r.ret);
		r = sys(e, bits, SYS(N_MMAP, bits), 0, 0, 3, 0x22, (uint64_t)-1, 0);
		CK(r.ret == errv(bits, 12), "%u bit: mmap of length 0 is -ENOMEM (%#llx)", bits, (unsigned long long)r.ret);
		r = sys(e, bits, SYS(N_GETPID, bits), 0, 0, 0, 0, 0, 0);
		CK(r.ret == 1, "%u bit: getpid is 1", bits);
		r = sys(e, bits, SYS(N_GETUID, bits), 0, 0, 0, 0, 0, 0);
		CK(r.ret == 1000, "%u bit: getuid is 1000, not root", bits);
		kgenome_emu_free(e);
	}
}

static void t_mmap(void)
{
	unsigned bits;

	for (bits = 32; bits <= 64; bits += 32) {
		struct kgenome_emu *e = mk(bits);
		struct res r;
		uint64_t a, b;
		char buf[16] = "";

		if (!e) {
			CK(0, "emulator");
			return;
		}
		r = sys(e, bits, SYS(N_MMAP, bits), 0, 0x2400, 3, 0x22, (uint64_t)-1, 0);
		a = r.ret;
		CK(r.done && a != 0 && !(a & 0xfff) && (bits == 64 || a < 0xfffff000ull), "%u bit: an unhinted anonymous mmap is page aligned and fits the guest's register (%#llx)",
		   bits, (unsigned long long)a);
		CK(get(e, a, 8) == 0 && get(e, a + 0x2ff8, 8) == 0, "%u bit: it is zero to the end of the rounded length", bits);
		CK(kgenome_emu_write(e, a + 0x2ff8, "12345678", 8), "%u bit: and writable there", bits);
		r = sys(e, bits, SYS(N_MMAP, bits), 0, 0x1000, 3, 0x22, (uint64_t)-1, 0);
		b = r.ret;
		CK(b != 0 && b != a && (b >= a + 0x4000 || b + 0x1000 <= a), "%u bit: the next mapping is elsewhere with a guard page between (%#llx)", bits, (unsigned long long)b);
		/* a mapping of the descriptor the scanned file was opened on is a window onto it */
		r = sys(e, bits, SYS(N_OPEN, bits), DATA, 0, 0, 0, 0, 0);
		r = sys(e, bits, SYS(N_MMAP, bits), 0, 0x1000, 1, 2, r.ret, 0);
		kgenome_emu_read(e, r.ret, buf, 9);
		CK(r.ret != 0 && !strncmp(buf, "SELF-FILE", 9), "%u bit: a file-backed map is a window onto the scanned file (%s)", bits, buf);
		kgenome_emu_free(e);
	}
	{   /* i386 old_mmap: one argument, a pointer to six words */
		struct kgenome_emu *e = mk(32);
		uint32_t args[6] = { 0, 0x1000, 3, 0x22, 0xffffffffu, 0 };
		struct res r;

		put(e, DATA + 0x100, args, sizeof args);
		r = sys(e, 32, N_OLDMMAP.a32, DATA + 0x100, 0, 0, 0, 0, 0);
		CK(r.ret != 0 && r.ret < 0xfffff000ull && !(r.ret & 0xfff), "32 bit: old_mmap(90) takes a pointer to its six arguments and maps (%#llx)", (unsigned long long)r.ret);
		kgenome_emu_free(e);
	}
}

static void t_structs(void)
{
	unsigned bits;
	uint64_t type[2], bsize[2], blocks[2], bfree[2], uptime[2], ram[2], rl_cur[2], rl_max[2];

	for (bits = 32; bits <= 64; bits += 32) {
		struct kgenome_emu *e = mk(bits);
		struct res r;
		unsigned w = bits / 8u, k = bits == 32 ? 0u : 1u;
		uint8_t guard[8];

		if (!e) {
			CK(0, "emulator");
			return;
		}
		/* struct stat: st_size where the ABI puts it, and nothing past the struct */
		memset(guard, 0x5a, sizeof guard);
		put(e, DATA + 0x200 + (bits == 32 ? 96u : 144u), guard, 8);
		r = sys(e, bits, SYS(N_FSTAT, bits), 3, DATA + 0x200, 0, 0, 0, 0);
		CK(r.ret == 0 && get(e, DATA + 0x200 + (bits == 32 ? 44u : 48u), 8) == sizeof SELF - 1u, "%u bit: st_size is the scanned file's size at offset %u", bits, bits == 32 ? 44u : 48u);
		CK(get(e, DATA + 0x200 + (bits == 32 ? 96u : 144u), 1) == 0x5a, "%u bit: nothing is written past the %u byte struct stat", bits, bits == 32 ? 96u : 144u);
		/* statfs: fields of the guest's word, the same values */
		r = sys(e, bits, SYS(N_STATFS, bits), DATA, DATA + 0x400, 0, 0, 0, 0);
		CK(r.ret == 0, "%u bit: statfs answers", bits);
		type[k] = word(e, bits, DATA + 0x400, 0);
		bsize[k] = word(e, bits, DATA + 0x400, 1);
		blocks[k] = word(e, bits, DATA + 0x400, 2);
		bfree[k] = word(e, bits, DATA + 0x400, 3);
		r = sys(e, bits, SYS(N_FSTATFS, bits), 3, DATA + 0x440, 0, 0, 0, 0);
		CK(r.ret == 0 && word(e, bits, DATA + 0x440, 0) == type[k], "%u bit: fstatfs agrees with statfs", bits);
		/* sysinfo: uptime is word 0; totalram follows the three load averages */
		r = sys(e, bits, SYS(N_SYSINFO, bits), DATA + 0x500, 0, 0, 0, 0, 0);
		uptime[k] = word(e, bits, DATA + 0x500, 0);
		ram[k] = word(e, bits, DATA + 0x500, 4) * (get(e, DATA + 0x500 + (bits == 32 ? 52u : 104u), 4) ? get(e, DATA + 0x500 + (bits == 32 ? 52u : 104u), 4) : 1u);
		CK(r.ret == 0 && uptime[k] > 0 && ram[k] > 0, "%u bit: sysinfo reports an uptime (%llu) and RAM (%llu bytes)", bits, (unsigned long long)uptime[k], (unsigned long long)ram[k]);
		/* rlimit: two words; RLIM_INFINITY is all ones in the word */
		r = sys(e, bits, SYS(bits == 32 ? N_UGETRLIMIT : N_GETRLIMIT, bits), 3, DATA + 0x600, 0, 0, 0, 0);
		rl_cur[k] = word(e, bits, DATA + 0x600, 0);
		rl_max[k] = word(e, bits, DATA + 0x600, 1);
		CK(r.ret == 0, "%u bit: getrlimit answers", bits);
		(void)w;
		kgenome_emu_free(e);
	}
	CK(type[0] == 0xEF53 && type[1] == 0xEF53, "statfs says ext4 in both guests (%#llx, %#llx)", (unsigned long long)type[0], (unsigned long long)type[1]);
	CK(bsize[0] == bsize[1] && blocks[0] == blocks[1] && bfree[0] == bfree[1], "statfs block size and counts are the same in both guests");
	CK(uptime[0] > 0 && uptime[1] > 0 && ram[0] == ram[1], "sysinfo reports the same RAM in both guests (%llu, %llu)", (unsigned long long)ram[0], (unsigned long long)ram[1]);
	CK((rl_cur[0] == 0xffffffffull || rl_cur[0] == rl_cur[1]) && (rl_max[0] == 0xffffffffull || rl_max[0] == rl_max[1]),
	   "rlimit values agree or are RLIM_INFINITY in the word (%llx/%llx vs %llx/%llx)", (unsigned long long)rl_cur[0], (unsigned long long)rl_max[0],
	   (unsigned long long)rl_cur[1], (unsigned long long)rl_max[1]);
}

static void t_vectors_and_time(void)
{
	unsigned bits;
	uint64_t nsec[2] = { 0, 0 };

	for (bits = 32; bits <= 64; bits += 32) {
		struct kgenome_emu *e = mk(bits);
		struct res r;
		uint8_t v[32];
		uint64_t b[2], l[2];
		unsigned at = 0, i, w = bits / 8u;
		uint64_t s1, s2;

		if (!e) {
			CK(0, "emulator");
			return;
		}
		/* readv: two entries of (base, length) in guest words fill two buffers in order from the file's start */
		b[0] = DATA + 0x800; b[1] = DATA + 0x810; l[0] = 2; l[1] = 3;
		for (i = 0; i < 2; i++) {
			memcpy(v + at, &b[i], w); at += w;
			memcpy(v + at, &l[i], w); at += w;
		}
		put(e, DATA + 0x700, v, at);
		r = sys(e, bits, SYS(N_LSEEK, bits), 3, 0, 0, 0, 0, 0);
		r = sys(e, bits, SYS(N_READV, bits), 3, DATA + 0x700, 2, 0, 0, 0);
		CK(r.ret == 5 && get(e, DATA + 0x800, 2) == 0x4553 && get(e, DATA + 0x810, 3) == 0x2d464cull, "%u bit: readv scatters SELF-F over two buffers of a %u byte iovec (ret %llu)", bits, w * 2u, (unsigned long long)r.ret);
		/* writev: the lengths add up */
		r = sys(e, bits, SYS(N_WRITEV, bits), 1, DATA + 0x700, 2, 0, 0, 0);
		CK(r.ret == 5, "%u bit: writev adds the iovec lengths (%llu)", bits, (unsigned long long)r.ret);
		/* clock_gettime: (sec, nsec) in guest words; the clock only moves forward */
		r = sys(e, bits, SYS(N_CLOCKGT, bits), 1, DATA + 0x900, 0, 0, 0, 0);
		s1 = word(e, bits, DATA + 0x900, 0);
		nsec[bits == 32 ? 0 : 1] = word(e, bits, DATA + 0x900, 1);
		CK(r.ret == 0 && nsec[bits == 32 ? 0 : 1] < 1000000000ull, "%u bit: clock_gettime fills a timespec of two %u byte words (nsec %llu)", bits, w, (unsigned long long)nsec[bits == 32 ? 0 : 1]);
		r = sys(e, bits, SYS(N_NANOSLP, bits), DATA + 0x940, 0, 0, 0, 0, 0);
		(void)r;
		r = sys(e, bits, SYS(N_CLOCKGT, bits), 1, DATA + 0x900, 0, 0, 0, 0);
		s2 = word(e, bits, DATA + 0x900, 0);
		CK(s2 >= s1, "%u bit: the clock does not go backwards (%llu then %llu)", bits, (unsigned long long)s1, (unsigned long long)s2);
		/* gettimeofday: (sec, usec) in guest words */
		r = sys(e, bits, SYS(N_GETTOD, bits), DATA + 0x980, 0, 0, 0, 0, 0);
		CK(r.ret == 0 && word(e, bits, DATA + 0x980, 1) < 1000000ull, "%u bit: gettimeofday fills (sec, usec) with usec below a million", bits);
		/* time() agrees with the struct form */
		r = sys(e, bits, SYS(N_TIME, bits), 0, 0, 0, 0, 0, 0);
		CK(r.ret >= word(e, bits, DATA + 0x980, 0) || bits == 32, "%u bit: time() is the same clock in seconds", bits);
		kgenome_emu_free(e);
	}
}

static void t_strings(void)
{
	unsigned bits;
	char un[2][6 * 65], cwd[2][32], rl[2][32], rnd[2][16];
	int64_t cwdlen[2];

	for (bits = 32; bits <= 64; bits += 32) {
		struct kgenome_emu *e = mk(bits);
		struct res r;
		unsigned k = bits == 32 ? 0u : 1u;

		if (!e) {
			CK(0, "emulator");
			return;
		}
		memset(un[k], 0, sizeof un[k]);
		r = sys(e, bits, SYS(N_UNAME, bits), DATA + 0xa00, 0, 0, 0, 0, 0);
		CK(r.ret == 0, "%u bit: uname", bits);
		kgenome_emu_read(e, DATA + 0xa00, un[k], sizeof un[k]);
		memset(cwd[k], 0, sizeof cwd[k]);
		r = sys(e, bits, SYS(N_GETCWD, bits), DATA + 0xc00, 32, 0, 0, 0, 0);
		cwdlen[k] = (int64_t)r.ret;
		kgenome_emu_read(e, DATA + 0xc00, cwd[k], 31);
		memset(rl[k], 0, sizeof rl[k]);
		put(e, DATA + 0xc80, "/proc/self/exe", 15);
		r = sys(e, bits, SYS(N_READLINK, bits), DATA + 0xc80, DATA + 0xd00, 32, 0, 0, 0);
		CK(r.ret == 14, "%u bit: readlink of /proc/self/exe is 14 bytes (%llu)", bits, (unsigned long long)r.ret);
		kgenome_emu_read(e, DATA + 0xd00, rl[k], 14);
		r = sys(e, bits, SYS(N_GETRANDOM, bits), DATA + 0xd80, 16, 0, 0, 0, 0);
		CK(r.ret == 16, "%u bit: getrandom returns the length", bits);
		kgenome_emu_read(e, DATA + 0xd80, rnd[k], 16);
		kgenome_emu_free(e);
	}
	CK(!strcmp(un[0], un[1]), "uname: the sysname is the same in both guests (%s, %s)", un[0], un[1]);
	CK(!memcmp(un[0] + 65, un[1] + 65, 65 * 3) , "uname: node name, release and version are the same in both guests");
	CK(cwdlen[0] == cwdlen[1] && !strcmp(cwd[0], cwd[1]), "getcwd: the same directory, the same length (%lld, %lld)", (long long)cwdlen[0], (long long)cwdlen[1]);
	CK(!strcmp(rl[0], rl[1]) && !strcmp(rl[0], "/proc/self/exe"), "readlink: the same target");
	CK(!memcmp(rnd[0], rnd[1], 16), "getrandom: the same deterministic bytes");
}

static void t_pipe_and_int80(void)
{
	unsigned bits;

	for (bits = 32; bits <= 64; bits += 32) {
		struct kgenome_emu *e = mk(bits);
		struct res r;
		uint32_t fds[2] = { 0xdeadbeefu, 0xdeadbeefu };

		if (!e) {
			CK(0, "emulator");
			return;
		}
		put(e, DATA + 0xe00, fds, 8);
		r = sys(e, bits, SYS(N_PIPE, bits), DATA + 0xe00, 0, 0, 0, 0, 0);
		CK(r.ret == 0 && get(e, DATA + 0xe00, 4) != 0xdeadbeefu && get(e, DATA + 0xe04, 4) != 0xdeadbeefu, "%u bit: pipe stores two 32 bit descriptors (ints, in both ABIs)", bits);
		kgenome_emu_free(e);
	}
	{   /* a 64 bit guest running `int 0x80` is served with the i386 numbers: 20 is getpid, 4 is write */
		struct kgenome_emu *e = mk(64);
		static const uint8_t c[] = { 0xb8, 20, 0, 0, 0, 0xcd, 0x80, 0xf4 };

		kgenome_emu_write(e, CODE, c, sizeof c);
		kgenome_emu_set_rip(e, CODE);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK + 0x8000);
		(void)kgenome_emu_run(e);
		CK(kgenome_emu_get_rip(e) == CODE + sizeof c - 1u && (kgenome_emu_get_reg(e, KGENOME_EMU_RAX) & 0xffffffffu) == 1, "int 0x80 in a 64 bit guest: eax=20 is getpid (the i386 table)");
		kgenome_emu_free(e);
	}
}

int main(void)
{
	t_return_width();
	t_mmap();
	t_structs();
	t_vectors_and_time();
	t_strings();
	t_pipe_and_int80();
	if (fails) {
		printf("diff_abi: FAILED (%d)\n", fails);
		return 1;
	}
	printf("diff_abi: ok\n");
	return 0;
}
