/*
 * cov_native.h - run ONE instruction sequence twice, on the host CPU and in the
 * interpreter, and compare what each left behind.
 *
 * WHY A REFERENCE AND NOT EXPECTED VALUES. The interpreter's integer, string, bit and vector
 * instructions are a few hundred lines that decide what a packer stub computes; a wrong flag or
 * a wrong carry is silent (the stub goes on and reads its payload from the wrong place). A table
 * of expected values is the author's reading of the manual a second time. The machine this
 * test runs on is the reference the manual describes, so the same bytes are executed natively
 * (an x86-64 host; a case is SKIPPED, visibly, when the host is another CPU) and the two
 * results are compared. What the architecture calls undefined is masked per instruction - the
 * mask is written next to the instruction, so a reader can see what is claimed.
 *
 * THE FRAME. Every case is the same prologue and epilogue around the bytes under test, so the
 * two sides cannot differ in how the inputs get in or the outputs get out:
 *
 *      io      4096 bytes. +0  rax rcx rdx rsi rdi rflags (in, as offsets for rsi/rdi), +48 the same
 *              out, +0x100 four xmm slots (xmm0 and xmm1 in, then out), +0x400 a data buffer.
 *      rsi, rdi   point into io (io base + the offset in the input), so a string or memory
 *                 instruction touches the same bytes natively and in the interpreter.
 *      RFLAGS     loaded with popfq before the bytes, read with pushfq after them.
 *
 * Natively the frame is called as `void f(io *)` from a RWX page; in the interpreter it is run
 * with a return address that points at a HLT. The generated code touches nothing outside io
 * and the stack, and every case is chosen so that it cannot trap (a divide is given a quotient
 * that fits). Nothing here writes a file.
 */

#ifndef COV_NATIVE_H
#define COV_NATIVE_H

#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <phenotype/emu.h>

#if defined(__x86_64__) && defined(__linux__)
#include <sys/mman.h>
#define CN_HOST 1
#else
#define CN_HOST 0
#endif

#define CN_IO       4096u
#define CN_O_RAX    0u
#define CN_O_RCX    8u
#define CN_O_RDX    16u
#define CN_O_RSI    24u
#define CN_O_RDI    32u
#define CN_O_FL     40u
#define CN_O_XMM    0x100u          /* in: xmm0 +0, xmm1 +16; out: xmm0 +32, xmm1 +48 */
#define CN_O_BUF    0x400u
#define CN_BUFLEN   (CN_IO - CN_O_BUF)

/* what the instructions under test may leave defined in RFLAGS: CF PF AF ZF SF OF, and DF */
#define CN_FL_CF 0x001ull
#define CN_FL_PF 0x004ull
#define CN_FL_AF 0x010ull
#define CN_FL_ZF 0x040ull
#define CN_FL_SF 0x080ull
#define CN_FL_OF 0x800ull
#define CN_FL_DF 0x400ull
#define CN_FL_ARITH (CN_FL_CF | CN_FL_PF | CN_FL_AF | CN_FL_ZF | CN_FL_SF | CN_FL_OF)

struct cn_io { uint8_t raw[CN_IO]; };

static inline uint64_t cn_get(const struct cn_io *x, unsigned off)
{
	uint64_t v;

	memcpy(&v, x->raw + off, 8);
	return v;
}

static inline void cn_put(struct cn_io *x, unsigned off, uint64_t v)
{
	memcpy(x->raw + off, &v, 8);
}

/* ---- the frame ------------------------------------------------------------------------- */

static unsigned cn_pre_len;       /* where the bytes under test start in the frame */

static unsigned cn_frame(uint8_t *c, const uint8_t *op, unsigned n)
{
	static const uint8_t pre[] = {
		0x49, 0x89, 0xf9,                   /* mov r9, rdi                */
		0x49, 0x8b, 0x01,                   /* mov rax, [r9]              */
		0x49, 0x8b, 0x49, 0x08,             /* mov rcx, [r9+8]            */
		0x49, 0x8b, 0x51, 0x10,             /* mov rdx, [r9+16]           */
		0x49, 0x8b, 0x71, 0x18,             /* mov rsi, [r9+24]           */
		0x4c, 0x01, 0xce,                   /* add rsi, r9                */
		0x49, 0x8b, 0x79, 0x20,             /* mov rdi, [r9+32]           */
		0x4c, 0x01, 0xcf,                   /* add rdi, r9                */
		0x41, 0x0f, 0x10, 0x81, 0x00, 0x01, 0, 0,   /* movups xmm0, [r9+0x100] */
		0x41, 0x0f, 0x10, 0x89, 0x10, 0x01, 0, 0,   /* movups xmm1, [r9+0x110] */
		0x41, 0xff, 0x71, 0x28,             /* push qword [r9+40]         */
		0x9d                                /* popfq                      */
	};
	static const uint8_t post[] = {
		0x9c,                               /* pushfq                     */
		0x41, 0x8f, 0x41, 0x58,             /* pop qword [r9+88]          */
		0x49, 0x89, 0x41, 0x30,             /* mov [r9+48], rax           */
		0x49, 0x89, 0x49, 0x38,             /* mov [r9+56], rcx           */
		0x49, 0x89, 0x51, 0x40,             /* mov [r9+64], rdx           */
		0x4c, 0x29, 0xce,                   /* sub rsi, r9                */
		0x49, 0x89, 0x71, 0x48,             /* mov [r9+72], rsi           */
		0x4c, 0x29, 0xcf,                   /* sub rdi, r9                */
		0x49, 0x89, 0x79, 0x50,             /* mov [r9+80], rdi           */
		0x41, 0x0f, 0x11, 0x81, 0x20, 0x01, 0, 0,   /* movups [r9+0x120], xmm0 */
		0x41, 0x0f, 0x11, 0x89, 0x30, 0x01, 0, 0,   /* movups [r9+0x130], xmm1 */
		0xdb, 0xe3,                         /* fninit: the host's x87 stack is left empty - the interpreter's own
		                                     * long double arithmetic (emu_x87.c) runs on it, and a case that left
		                                     * values behind would make the next one overflow it */
		0xfc,                               /* cld                        */
		0xc3                                /* ret                        */
	};
	unsigned k = 0;

	memcpy(c, pre, sizeof pre);
	k = (unsigned)sizeof pre;
	cn_pre_len = k;
	memcpy(c + k, op, n);
	k += n;
	memcpy(c + k, post, sizeof post);
	return k + (unsigned)sizeof post;
}

/* ---- the host --------------------------------------------------------------------------- */

#if CN_HOST
static uint8_t *cn_page;

/*
 * A HOST FAULT IS AN ANSWER. A divide whose quotient does not fit, or whose divisor is zero, is #DE on
 * the CPU and SIGFPE to this process; the handler jumps back to cn_native, which reports "trapped"
 * (cn_trapped) instead of a result, and cn_case then requires the interpreter to end with a FAULT
 * stop - the same event, not an instruction it lacks. Only SIGFPE, and only while a native case is
 * running: any other signal, or one outside a case, is not caught and kills the test as it should.
 */
static sigjmp_buf cn_jb;
static volatile sig_atomic_t cn_in_native;
static int cn_trapped;

static void cn_on_fpe(int sig)
{
	if (cn_in_native)
		siglongjmp(cn_jb, 1);
	signal(sig, SIG_DFL);
	raise(sig);
}

static int cn_native(const uint8_t *op, unsigned n, const struct cn_io *in, struct cn_io *out)
{
	void (*f)(void *);
	uint8_t *io;
	unsigned len;
	static int armed;

	cn_trapped = 0;
	if (!armed) {
		struct sigaction sa;

		memset(&sa, 0, sizeof sa);
		sa.sa_handler = cn_on_fpe;
		sa.sa_flags = SA_NODEFER;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGFPE, &sa, NULL))
			return 0;
		armed = 1;
	}

	if (!cn_page) {
		cn_page = mmap(NULL, 8192, PROT_READ | PROT_WRITE | PROT_EXEC,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (cn_page == MAP_FAILED) {
			cn_page = NULL;
			return 0;
		}
	}
	io = cn_page + 4096;               /* a page of its own, so a stray store is not code */
	len = cn_frame(cn_page, op, n);
	(void)len;
	memcpy(io, in->raw, CN_IO);
	memcpy(&f, &(void *){ cn_page }, sizeof f);
	if (sigsetjmp(cn_jb, 1)) {
		cn_in_native = 0;
		cn_trapped = 1;
		memcpy(out->raw, in->raw, CN_IO);
		return 1;
	}
	cn_in_native = 1;
	f(io);
	cn_in_native = 0;
	memcpy(out->raw, io, CN_IO);
	return 1;
}
#else
static int cn_trapped;

static int cn_native(const uint8_t *op, unsigned n, const struct cn_io *in, struct cn_io *out)
{
	(void)op; (void)n; (void)in; (void)out;
	return 0;
}
#endif

/* ---- the interpreter -------------------------------------------------------------------- */

#define CN_CODE  0x400000ull
#define CN_HLT   (CN_CODE + 0xf00ull)
#define CN_DATA  0x500000ull
#define CN_STACK 0x7ff00000ull

struct cn_emu {
	enum kgenome_emu_stop stop;
	char                  detail[96];
	int                   done;         /* ended on the HLT after the frame's return */
	uint64_t              rip;
};

/*
 * ONE INTERPRETER, RE-ARMED FOR EVERY CASE. Building a machine costs about 130 microseconds (its page tables
 * and caches) against a run of under one, so a sweep of tens of thousands of cases made a machine each would be
 * 99% setup. The machine is made once per width and, for each case, the frame and the io block are written
 * over the same pages, the registers are cleared and the run starts again at the frame. kgenome_emu_run
 * is documented to carry on from where a run stopped, and what stops it here is the HLT at the end, so
 * a case starts from the state a fresh machine has except for the budget counters; cn_emulate_fresh makes
 * a new machine and is what the test of this file uses to show the two give the same answers.
 */
static struct kgenome_emu *cn_machine[2];

static struct kgenome_emu *cn_make(unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	static uint8_t blank[4096];

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = bits;
	cfg.max_insn = 1000000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	kgenome_emu_map(e, CN_CODE, blank, sizeof blank, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X | KGENOME_EMU_W);
	kgenome_emu_map(e, CN_DATA, blank, sizeof blank, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, CN_STACK, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	return e;
}

static int cn_run_on(struct kgenome_emu *e, const uint8_t *op, unsigned n, const struct cn_io *in,
		     struct cn_io *out, struct cn_emu *r)
{
	uint8_t code[4096];
	uint64_t ret = CN_HLT, rsp = CN_STACK + 0x800;
	const char *d;
	unsigned k;

	memset(code, 0xcc, sizeof code);
	cn_frame(code, op, n);
	code[0xf00] = 0xf4;
	kgenome_emu_write(e, CN_CODE, code, sizeof code);
	kgenome_emu_write(e, CN_DATA, in->raw, CN_IO);
	kgenome_emu_write(e, rsp, &ret, 8);
	for (k = 0; k < KGENOME_EMU_NGPR; k++)
		kgenome_emu_set_reg(e, k, 0);
	kgenome_emu_set_rip(e, CN_CODE);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, rsp);
	kgenome_emu_set_reg(e, KGENOME_EMU_RDI, CN_DATA);
	kgenome_emu_set_max_insn(e, kgenome_emu_insn_count(e) + 1000000u);
	r->stop = kgenome_emu_run(e);
	r->rip = kgenome_emu_get_rip(e);
	d = kgenome_emu_stop_detail(e);
	snprintf(r->detail, sizeof r->detail, "%s", d ? d : "");
	r->done = r->rip == CN_HLT;
	kgenome_emu_read(e, CN_DATA, out->raw, CN_IO);
	return 1;
}

static __attribute__((unused)) int cn_emulate_fresh(const uint8_t *op, unsigned n, const struct cn_io *in, struct cn_io *out,
			    unsigned bits, struct cn_emu *r)
{
	struct kgenome_emu *e = cn_make(bits);
	int ok;

	if (!e)
		return 0;
	ok = cn_run_on(e, op, n, in, out, r);
	kgenome_emu_free(e);
	return ok;
}

static int cn_emulate(const uint8_t *op, unsigned n, const struct cn_io *in, struct cn_io *out,
		      unsigned bits, struct cn_emu *r)
{
	unsigned w = bits == 32 ? 1u : 0u;

	if (!cn_machine[w])
		cn_machine[w] = cn_make(bits);
	if (!cn_machine[w])
		return 0;
	return cn_run_on(cn_machine[w], op, n, in, out, r);
}

/* ---- the comparison --------------------------------------------------------------------- */

static uint64_t cn_rng_state;

static uint64_t cn_rng(void)
{
	uint64_t z = (cn_rng_state += 0x9e3779b97f4a7c15ull);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	return z ^ (z >> 31);
}

/* a value that is often an edge: 0, 1, all ones, the sign bit, a single bit, or noise */
static __attribute__((unused)) uint64_t cn_edge(unsigned size)
{
	uint64_t m = size >= 8 ? ~0ull : ((1ull << (size * 8u)) - 1ull);
	uint64_t r = cn_rng();

	switch (r & 15u) {
	case 0:  return 0;
	case 1:  return 1;
	case 2:  return m;
	case 3:  return (m >> 1) + 1ull;
	case 4:  return m >> 1;
	case 5:  return 1ull << ((r >> 8) % (size * 8u));
	case 6:  return m ^ (1ull << ((r >> 8) % (size * 8u)));
	default: return cn_rng();
	}
}

struct cn_stat {
	unsigned cases, native_ok, diffs, unsupported;
	char     first[8][300];
	unsigned nfirst;
	char     names[16][32];     /* the instructions that differed or were refused, once each */
	unsigned nnames;
};

/* the outputs of the last case, native and interpreter, for a test that wants to look further
 * (cn_trapped: the host raised #DE on it, and `cn_la` is then the input) */
static struct cn_io cn_la, cn_lb;

static void cn_fill_buf(struct cn_io *x, unsigned alphabet)
{
	unsigned i;

	for (i = 0; i < CN_BUFLEN; i++)
		x->raw[CN_O_BUF + i] = (uint8_t)(alphabet ? cn_rng() % alphabet : cn_rng());
}

static void cn_note(struct cn_stat *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void cn_name(struct cn_stat *s, const char *nm)
{
	unsigned i;

	for (i = 0; i < s->nnames; i++)
		if (!strncmp(s->names[i], nm, sizeof s->names[0] - 1))
			return;
	if (s->nnames < 16)
		snprintf(s->names[s->nnames++], sizeof s->names[0], "%s", nm);
}

static void cn_note(struct cn_stat *s, const char *fmt, ...)
{
	va_list ap;

	if (s->nfirst >= 8)
		return;
	va_start(ap, fmt);
	vsnprintf(s->first[s->nfirst++], sizeof s->first[0], fmt, ap);
	va_end(ap);
}

/*
 * One case: the bytes `op`, the inputs in `in`, and which RFLAGS bits are defined afterwards
 * (`flmask`; DF is always compared). `xmask` says which of the 32 output bytes of xmm0 (bits 0-15) and
 * xmm1 (bits 16-31) are compared, `cmpbuf` adds the data buffer.
 * Returns 1 when both sides finished and agree, 0 on a difference, -1 when the interpreter
 * stopped before the HLT (unsupported/fault: counted apart, since it is a gap and not a wrong
 * answer) and -2 when the host could not run it.
 */
static int cn_case(struct cn_stat *s, const char *name, const uint8_t *op, unsigned n,
		   const struct cn_io *in, uint64_t flmask, unsigned bits, uint32_t xmask, int cmpbuf)
{
	struct cn_io a, b;
	struct cn_emu r;
	unsigned k, bad = 0;
	char why[200] = "";
	static const char *rn[] = { "rax", "rcx", "rdx", "rsi", "rdi" };

	s->cases++;
	if (!cn_native(op, n, in, &a))
		return -2;
	s->native_ok++;
	if (!cn_emulate(op, n, in, &b, bits, &r))
		return -2;
	cn_la = a;
	cn_lb = b;
	if (cn_trapped) {
		/* the CPU raised #DE: the interpreter has to raise it too - a FAULT stop that names it, the
		 * instruction having written nothing (the frame's own stores to io do not happen either) */
		if (r.stop == KGENOME_EMU_STOP_FAULT && !strncmp(r.detail, "div", 3) && !r.done)
			return 1;
		s->diffs++;
		cn_name(s, name);
		cn_note(s, "%s: the host trapped (#DE); the interpreter ended with %s (%s)", name,
			kgenome_emu_stop_name(r.stop), r.detail);
		return 0;
	}
	if (!r.done) {
		s->unsupported++;
		cn_name(s, name);
		cn_note(s, "%s: interpreter stopped (%s: %s) rip=%#llx", name,
			kgenome_emu_stop_name(r.stop), r.detail, (unsigned long long)r.rip);
		return -1;
	}
	for (k = 0; k < 5; k++) {
		uint64_t x = cn_get(&a, 48u + k * 8u), y = cn_get(&b, 48u + k * 8u);

		if (bits == 32) {
			x &= 0xffffffffull;
			y &= 0xffffffffull;
		}
		if (x != y && !bad++)
			snprintf(why, sizeof why, "%s native=%#llx emu=%#llx", rn[k],
				 (unsigned long long)x, (unsigned long long)y);
	}
	{
		uint64_t fm = (flmask | CN_FL_DF);
		uint64_t x = cn_get(&a, 88u) & fm, y = cn_get(&b, 88u) & fm;

		if (x != y && !bad++)
			snprintf(why, sizeof why, "rflags native=%#llx emu=%#llx (mask %#llx)",
				 (unsigned long long)x, (unsigned long long)y, (unsigned long long)fm);
	}
	for (k = 0; k < 32 && xmask; k++)
		if (((xmask >> k) & 1u) && a.raw[0x120 + k] != b.raw[0x120 + k]) {
			if (!bad++)
				snprintf(why, sizeof why, "xmm byte %u native=%016llx_%016llx emu=%016llx_%016llx", k,
					 (unsigned long long)cn_get(&a, 0x128), (unsigned long long)cn_get(&a, 0x120),
					 (unsigned long long)cn_get(&b, 0x128), (unsigned long long)cn_get(&b, 0x120));
			break;
		}
	if (cmpbuf && memcmp(a.raw + CN_O_BUF, b.raw + CN_O_BUF, CN_BUFLEN) && !bad++) {
		for (k = 0; k < CN_BUFLEN && a.raw[CN_O_BUF + k] == b.raw[CN_O_BUF + k]; k++)
			;
		snprintf(why, sizeof why, "memory differs at buf+%u native=%02x emu=%02x", k,
			 a.raw[CN_O_BUF + k], b.raw[CN_O_BUF + k]);
	}
	if (bad) {
		char hex[64] = "";
		unsigned i;

		s->diffs++;
		cn_name(s, name);
		for (i = 0; i < n && i < 10; i++)
			snprintf(hex + i * 3, sizeof hex - i * 3, "%02x ", op[i]);
		cn_note(s, "%s [%s]: in rax=%#llx rcx=%#llx rdx=%#llx fl=%#llx: %s", name, hex,
			(unsigned long long)cn_get(in, 0), (unsigned long long)cn_get(in, 8),
			(unsigned long long)cn_get(in, 16), (unsigned long long)cn_get(in, 40), why);
		return 0;
	}
	return 1;
}

static void cn_print(const char *family, const struct cn_stat *s)
{
	unsigned i;

	printf("  %-22s %6u case(s), %u unsupported, %u differ\n", family, s->cases, s->unsupported,
	       s->diffs);
	for (i = 0; i < s->nfirst; i++)
		printf("      %s\n", s->first[i]);
	if (s->nnames) {
		printf("      instructions:");
		for (i = 0; i < s->nnames; i++)
			printf(" [%s]", s->names[i]);
		printf("\n");
	}
}

/* a fresh input: random registers and flags (arithmetic bits only), a buffer */
static void cn_input(struct cn_io *x, int df)
{
	memset(x->raw, 0, CN_IO);
	cn_put(x, CN_O_RAX, cn_rng());
	cn_put(x, CN_O_RCX, cn_rng());
	cn_put(x, CN_O_RDX, cn_rng());
	cn_put(x, CN_O_RSI, 0);
	cn_put(x, CN_O_RDI, 0);
	cn_put(x, CN_O_FL, (cn_rng() & CN_FL_ARITH) | 2ull | (df ? CN_FL_DF : 0ull));
}

#endif /* COV_NATIVE_H */
