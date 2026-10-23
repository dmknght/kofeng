/*
 * diag_graph_bin - the binary graph's false claims and wrong reports, each held by a hand-assembled ELF.
 *
 * The routes that link nodes in an executable (the sweep, the wrapper analysis, the run) answer "this
 * argument came from that node" as PROVEN or MAY. An audit found the sweep saying PROVEN where the
 * program does not say so, and two status words that named the wrong reason. Every case below is a
 * program of a few instructions written out by hand from the instruction set manual (so that a decoder
 * bug cannot make a test agree with itself); each of them is the smallest program that shows the defect,
 * and each has a CONTROL beside it that must keep its link, because a fix that kills too much looks
 * exactly like a fix that works when only the defect is checked.
 *
 *   W1   a register carried across `ret` into the NEXT function: a write that takes rdi in B is linked to
 *        the socket A made. (After a `ret` the code that follows is reached only by a jump from earlier
 *        in the function, or it is another function.)
 *   W1b  the same, seen through a wrapper called from three places: the last producer in address order
 *        was linked to the wrapper's one syscall as PROVEN.
 *   W3   a callee that overwrites rdi between the producer and the consumer.
 *   W5   a callee that overwrites rax, the register the producer's result is read from.
 *   W4   two producers on the two arms of a branch, joined before the consumer: both reach it, neither
 *        is certain. One arm only: the other path has no such value.
 *   W6   a partial register write (`mov di,ax`): the decision is written here as a test.
 *   C1   the wrapper levels are a fixpoint; a chain of D functions each calling the next, in ascending
 *        address order, found ONE function per pass and each pass looked at every call target: D*D
 *        looks. Counted, not timed: the test reads how many times the retry question was asked.
 *   S1   a program that ends in exit was reported KGENOME_TRUNCATED: the run's last step was not read, the
 *        exit was not seen, and the run went on until its "nothing new" bound.
 *   S2   an image that could not be built (the entry is past the bytes the file holds) was reported as
 *        out of memory; a budget refusal likewise.
 *   U1   the lineage join compared two empty tables with memcmp(NULL, NULL, 0). Caught here without a
 *        sanitiser: the four mem* calls and qsort are wrapped at link time and count a NULL argument.
 *
 * Why the old tests did not see them: (W1, W3, W5, W4) the cases ran the sweep over programs where the
 * producer and the consumer sat in ONE straight line, so no test had a ret, a call or a branch between
 * them (b: executed without the boundary input); (W1b) tests/unit/diag_wrapper_caller.c checks the
 * nodes the callers make and not which MUST links the wrapper's own node carries (c); (C1) diag_wrapper_scale
 * runs depth 200 and checks the RESULT, not the work (c); (S1) every emulate-route test that ends in
 * exit asserted the nodes, none asserted the status (c); (S2) the failure line was never executed (a);
 * (U1) only a sanitised build sees it and no suite ran the lineage over a diamond with no stack slot (a).
 */

#include <kgenome.h>

#include "hk.h"

/* ---- the wrapped calls: link time, no change in the product ------------------------------------ */

static unsigned null_mem;       /* a memcmp, memcpy, memmove, memset or qsort call that got NULL, however many bytes */
static unsigned retry_calls;    /* the wrapper fixpoint's "could this function come out differently" */

int __real_memcmp(const void *, const void *, size_t);
void *__real_memcpy(void *, const void *, size_t);
void *__real_memmove(void *, const void *, size_t);
void *__real_memset(void *, int, size_t);
void __real_qsort(void *, size_t, size_t, int (*)(const void *, const void *));
int __real_kgenome_diag_wrapper_tseen_retry(const void *, const void *);

int __wrap_memcmp(const void *a, const void *b, size_t n);
void *__wrap_memcpy(void *a, const void *b, size_t n);
void *__wrap_memmove(void *a, const void *b, size_t n);
void *__wrap_memset(void *a, int c, size_t n);
void __wrap_qsort(void *a, size_t n, size_t sz, int (*f)(const void *, const void *));
int __wrap_kgenome_diag_wrapper_tseen_retry(const void *c, const void *t);

int __wrap_memcmp(const void *a, const void *b, size_t n)
{
	if (!a || !b)
		null_mem++;
	return __real_memcmp(a, b, n);
}
void *__wrap_memcpy(void *a, const void *b, size_t n)
{
	if (!a || !b)
		null_mem++;
	return __real_memcpy(a, b, n);
}
void *__wrap_memmove(void *a, const void *b, size_t n)
{
	if (!a || !b)
		null_mem++;
	return __real_memmove(a, b, n);
}
void *__wrap_memset(void *a, int c, size_t n)
{
	if (!a)
		null_mem++;
	return __real_memset(a, c, n);
}
void __wrap_qsort(void *a, size_t n, size_t sz, int (*f)(const void *, const void *))
{
	if (!a)
		null_mem++;
	__real_qsort(a, n, sz, f);
}
int __wrap_kgenome_diag_wrapper_tseen_retry(const void *c, const void *t)
{
	retry_calls++;
	return __real_kgenome_diag_wrapper_tseen_retry(c, t);
}

/* ---- the assembler: just the bytes these programs need ------------------------------------------- */

#define CODE_MAX (1u << 16)

struct cb {
	uint8_t  b[CODE_MAX];
	unsigned n;
};

static void emit(struct cb *c, const uint8_t *p, unsigned n)
{
	if (c->n + n <= CODE_MAX) {
		memcpy(c->b + c->n, p, n);
		c->n += n;
	}
}
#define E(c, ...) do { static const uint8_t b_[] = { __VA_ARGS__ }; emit((c), b_, (unsigned)sizeof b_); } while (0)

static void p32(uint8_t *b, unsigned at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void p64(uint8_t *b, unsigned at, uint64_t v)
{
	p32(b, at, (uint32_t)v);
	p32(b, at + 4u, (uint32_t)(v >> 32));
}

/* socket(2, 1, 0): rax holds the descriptor; rdi, rsi, rdx hold constants afterwards */
static void sock(struct cb *c)
{
	E(c, 0xb8, 41, 0, 0, 0, 0xbf, 2, 0, 0, 0, 0xbe, 1, 0, 0, 0, 0x31, 0xd2, 0x0f, 0x05);
}
static void mov_rdi_rax(struct cb *c) { E(c, 0x48, 0x89, 0xc7); }
static void write_sys(struct cb *c) { E(c, 0xb8, 1, 0, 0, 0, 0x0f, 0x05); }
static void exit_sys(struct cb *c) { E(c, 0xb8, 60, 0, 0, 0, 0x0f, 0x05); }
static void ret(struct cb *c) { E(c, 0xc3); }
static void pad(struct cb *c, unsigned n) { while (n--) E(c, 0x90); }

/* call rel32 to a code offset already known */
static void call_to(struct cb *c, unsigned target)
{
	if (c->n + 5u > CODE_MAX)
		return;
	c->b[c->n] = 0xe8;
	p32(c->b, c->n + 1u, (uint32_t)(target - (c->n + 5u)));
	c->n += 5u;
}
/* a forward jz: the offset of its displacement, patched by here() */
static unsigned jz_fwd(struct cb *c)
{
	unsigned at;

	E(c, 0x0f, 0x84, 0, 0, 0, 0);
	at = c->n - 4u;
	return at;
}
static unsigned jmp_fwd(struct cb *c)
{
	unsigned at;

	E(c, 0xe9, 0, 0, 0, 0);
	at = c->n - 4u;
	return at;
}
static void here(struct cb *c, unsigned hole)
{
	p32(c->b, hole, (uint32_t)(c->n - (hole + 4u)));
}
static void test_rcx(struct cb *c) { E(c, 0x48, 0x85, 0xc9); }

static unsigned elf_machine = 0x3e;     /* what the next image says it is: x86-64, or 0xb7 for AArch64 */

/* An ELF64 with one RWX PT_LOAD from offset zero; the code is at +0x78, the entry too. */
static uint64_t elf64(uint8_t *b, const struct cb *c, uint64_t entry_va)
{
	memset(b, 0, 0x78u + c->n);
	memcpy(b, "\177ELF\2\1\1", 7);
	b[16] = 2; b[18] = (uint8_t)elf_machine; b[19] = (uint8_t)(elf_machine >> 8); b[20] = 1;
	p64(b, 24, entry_va ? entry_va : 0x400078u);
	p64(b, 32, 64);
	b[52] = 64; b[54] = 56; b[56] = 1;
	p32(b, 64, 1);
	p32(b, 68, 7);
	p64(b, 80, 0x400000u);
	p64(b, 96, 0x78u + c->n);
	p64(b, 104, 0x78u + c->n);
	memcpy(b + 0x78, c->b, c->n);
	return 0x78u + c->n;
}

/* An ELF32 (ARM) with one RWX PT_LOAD from offset zero; the code is at +0x54, the entry too. */
static uint64_t elf32(uint8_t *b, const struct cb *c)
{
	memset(b, 0, 0x54u + c->n);
	memcpy(b, "\177ELF\1\1\1", 7);
	b[16] = 2; b[18] = 40; b[20] = 1;
	p32(b, 24, 0x10054u);
	p32(b, 28, 52);
	b[40] = 52; b[42] = 32; b[44] = 1;
	p32(b, 52, 1);
	p32(b, 60, 0x10000u);
	p32(b, 64, 0x10000u);
	p32(b, 68, 0x54u + c->n);
	p32(b, 72, 0x54u + c->n);
	p32(b, 76, 7);
	memcpy(b + 0x54, c->b, c->n);
	return 0x54u + c->n;
}

/* ---- the scan and what it found ------------------------------------------------------------------ */

static uint8_t img[CODE_MAX + 0x100];
static struct kgenome_elf_info ei;

static struct kgenome_diag_scan *scan_img(uint64_t n, unsigned run, const struct kgenome_budget *bud,
					  unsigned stages, struct kgenome_obj *o)
{
	struct kgenome_diag_inputs in;

	memset(&ei, 0, sizeof ei);
	memset(o, 0, sizeof *o);
	if (!kgenome_elf_image_parse(kof_buf_make(img, n), &ei, o)) {
		printf("  FAIL %s:%d  the image did not parse\n", __FILE__, __LINE__);
		hk_fails++;
		return NULL;
	}
	o->file_header = &ei;
	memset(&in, 0, sizeof in);
	in.budget = bud;
	in.lineage_stages = stages;
	return kgenome_diag_scan_with_inputs(o, img, n, run, &in);
}

static struct kgenome_diag_scan *scan_cb(const struct cb *c, unsigned run)
{
	static struct kgenome_obj o;

	return scan_img(elf64(img, c, 0), run, NULL, 0, &o);
}

static int is_write(uint16_t cap)
{
	return cap == KGENOME_NUCLEO_MEM_WRITE || cap == KGENOME_NUCLEO_WRITE || cap == KGENOME_NUCLEO_NET_WRITE;
}

/* The links that reach a write node from a socket node: PROVEN, MAY. */
static void write_links(const struct kgenome_diag_scan *s, unsigned *must, unsigned *may)
{
	uint32_t i, cnt = kgenome_diag_scan_count(s);
	unsigned k;

	*must = *may = 0;
	for (i = 0; i < cnt; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		if (!is_write(h->cap))
			continue;
		for (k = 0; k < h->n_in; k++) {
			const struct kgenome_diag_hit *p = h->in[k].from < cnt ? kgenome_diag_scan_at(s, h->in[k].from) : NULL;

			if (!p || p->cap != KGENOME_NUCLEO_NET_OPEN)
				continue;
			if (h->in[k].how == KGENOME_DIAG_LINK_MAY)
				(*may)++;
			else
				(*must)++;
		}
	}
}

/* what a case says: the links into the write, and the status. */
struct want {
	const char *what;
	unsigned    must, may;
};

static void expect(const char *what, const struct cb *c, unsigned run, unsigned must, unsigned may)
{
	struct kgenome_diag_scan *s = scan_cb(c, run);
	unsigned m = 0, y = 0;

	if (!s) {
		printf("  FAIL %s: no scan\n", what);
		hk_fails++;
		return;
	}
	write_links(s, &m, &y);
	if (m != must || y != may) {
		printf("  FAIL %s: PROVEN %u MAY %u, wanted PROVEN %u MAY %u\n", what, m, y, must, may);
		hk_fails++;
	}
	kgenome_diag_scan_free(s);
}

/* ---- the cases ----------------------------------------------------------------------------------- */

#define SWEEP KGENOME_DIAG_RUN_SYSCALL

static void t_ret(void)
{
	static struct cb c;

	/* W1: A makes the socket and keeps it in rdi, returns; B (the next function) writes. */
	c.n = 0; sock(&c); mov_rdi_rax(&c); ret(&c); pad(&c, 20); write_sys(&c); ret(&c);
	expect("W1 socket in A, write in B", &c, SWEEP, 0, 0);
	/* the far form: a page of padding between */
	c.n = 0; sock(&c); mov_rdi_rax(&c); ret(&c); pad(&c, 4200); write_sys(&c); ret(&c);
	expect("W1 far", &c, SWEEP, 0, 0);
	/* control: the producer never put it in rdi */
	c.n = 0; sock(&c); ret(&c); pad(&c, 20); write_sys(&c); ret(&c);
	expect("W1 control, no rdi", &c, SWEEP, 0, 0);
	/* control: one straight line keeps its link */
	c.n = 0; sock(&c); mov_rdi_rax(&c); write_sys(&c); ret(&c);
	expect("W1 control, one function", &c, SWEEP, 1, 0);
	/* control: code after a ret that a jump before it reaches still holds the value */
	{
		unsigned h;

		c.n = 0; sock(&c); mov_rdi_rax(&c); test_rcx(&c); h = jz_fwd(&c); ret(&c); here(&c, h);
		write_sys(&c); ret(&c);
		expect("W1 control, jumped over the ret", &c, SWEEP, 1, 0);
	}
}

static void t_call(void)
{
	static struct cb c;
	unsigned g, h;

	/* W3: the callee zeroes edi between the producer and the write */
	c.n = 0; sock(&c); mov_rdi_rax(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c); exit_sys(&c);
	g = c.n; E(&c, 0x31, 0xff); ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("W3 callee writes rdi", &c, SWEEP, 0, 0);
	/* control: a callee that leaves it alone */
	c.n = 0; sock(&c); mov_rdi_rax(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c); exit_sys(&c);
	g = c.n; ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("W3 control, callee only returns", &c, SWEEP, 1, 0);
	/* control: the register the ABI makes the callee keep */
	c.n = 0; sock(&c); E(&c, 0x48, 0x89, 0xc3); h = c.n; E(&c, 0xe8, 0, 0, 0, 0);
	E(&c, 0x48, 0x89, 0xdf); write_sys(&c); exit_sys(&c);
	g = c.n; ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("W3 control, rbx across a call", &c, SWEEP, 1, 0);
	/* a callee that calls: what it does to rdi is not known here, so the link is MAY and not gone */
	c.n = 0; sock(&c); mov_rdi_rax(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c); exit_sys(&c);
	g = c.n; E(&c, 0xe8, 1, 0, 0, 0); ret(&c); ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("W3 callee calls", &c, SWEEP, 0, 1);
	/* an indirect call: the same */
	c.n = 0; sock(&c); mov_rdi_rax(&c); E(&c, 0xff, 0xd1); write_sys(&c); exit_sys(&c);
	expect("W3 indirect call", &c, SWEEP, 0, 1);
	/* the get-pc idiom is not a call: `call next; pop rsi` keeps everything */
	c.n = 0; sock(&c); mov_rdi_rax(&c); E(&c, 0xe8, 0, 0, 0, 0, 0x5e); write_sys(&c); exit_sys(&c);
	expect("W3 control, call next / pop", &c, SWEEP, 1, 0);
	/* `call next` is the address of the next instruction whatever follows it: here `add rsp,8` takes it back */
	c.n = 0; sock(&c); mov_rdi_rax(&c); E(&c, 0xe8, 0, 0, 0, 0, 0x48, 0x83, 0xc4, 0x08); write_sys(&c); exit_sys(&c);
	expect("W3 control, call next / add rsp", &c, SWEEP, 1, 0);

	/* W5: the callee overwrites rax, and the program then reads rax as if it were the socket */
	c.n = 0; sock(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); mov_rdi_rax(&c); write_sys(&c); exit_sys(&c);
	g = c.n; E(&c, 0xb8, 5, 0, 0, 0); ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("W5 callee writes rax", &c, SWEEP, 0, 0);
	/* control: it does not */
	c.n = 0; sock(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); mov_rdi_rax(&c); write_sys(&c); exit_sys(&c);
	g = c.n; ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("W5 control, callee only returns", &c, SWEEP, 1, 0);
}

static void t_arms(void)
{
	static struct cb c;
	unsigned a, b;

	/* W4: two sockets, one on each arm of a branch, both put in rdi, joined at the write */
	c.n = 0;
	E(&c, 0x59);                                    /* pop rcx */
	test_rcx(&c);
	a = jz_fwd(&c);
	sock(&c); mov_rdi_rax(&c);
	b = jmp_fwd(&c);
	here(&c, a);
	sock(&c); mov_rdi_rax(&c);
	here(&c, b);
	write_sys(&c); exit_sys(&c);
	expect("W4 two producers", &c, SWEEP, 0, 2);
	/* one arm only: the path round it has no such value */
	c.n = 0; test_rcx(&c); a = jz_fwd(&c); sock(&c); mov_rdi_rax(&c); here(&c, a); write_sys(&c); exit_sys(&c);
	expect("W4 one arm", &c, SWEEP, 0, 1);
	/* control: the branch is taken round something that does not touch it */
	c.n = 0; sock(&c); mov_rdi_rax(&c); test_rcx(&c); a = jz_fwd(&c); E(&c, 0x48, 0xff, 0xc3); here(&c, a);
	write_sys(&c); exit_sys(&c);
	expect("W4 control, the same value on both paths", &c, SWEEP, 1, 0);
}

/* W6: the decision. A partial write of a register is not a copy of the value: the sweep keeps no link
 * through it (the origin is forgotten, as for any write). The run, which sees the value itself, links by
 * value and says PROVEN - what it demonstrated - and is the one place a truncating copy still links. */
static void t_partial(void)
{
	static struct cb c;

	c.n = 0; sock(&c); E(&c, 0x31, 0xff, 0x66, 0x89, 0xc7); write_sys(&c); exit_sys(&c);
	expect("W6 sweep: mov di,ax", &c, SWEEP, 0, 0);
	expect("W6 run: mov di,ax links by value", &c, SWEEP | KGENOME_DIAG_RUN_EMULATE, 1, 0);
}

/* W1b: three functions each make a socket into rdi and call the one function that writes */
static void t_fanin(void)
{
	static struct cb c;
	unsigned f, w = 3u * 64u;

	c.n = 0;
	for (f = 0; f < 3u; f++) {
		sock(&c); mov_rdi_rax(&c); call_to(&c, w); ret(&c);
		pad(&c, (f + 1u) * 64u - c.n);
	}
	write_sys(&c); ret(&c);
	expect("W1b sweep", &c, SWEEP, 0, 0);
	expect("W1b sweep + lineage", &c, SWEEP | KGENOME_DIAG_RUN_LINEAGE, 0, 0);
}

static void want_status(const char *what, const struct kgenome_diag_scan *s, enum kgenome_status want)
{
	enum kgenome_status st = kgenome_diag_scan_status(s);

	if (st != want) {
		printf("  FAIL %s: status %s, wanted %s\n", what, kgenome_status_name(st), kgenome_status_name(want));
		hk_fails++;
	}
}

/* S1 */
static void t_exit_status(void)
{
	static struct cb c;
	struct kgenome_diag_scan *s;

	c.n = 0; E(&c, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05);
	s = scan_cb(&c, KGENOME_DIAG_RUN_EMULATE);
	CK(s != NULL);
	if (s) {
		want_status("S1 exit(0)", s, KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
	c.n = 0; write_sys(&c); exit_sys(&c);
	s = scan_cb(&c, KGENOME_DIAG_RUN_EMULATE);
	CK(s != NULL);
	if (s) {
		want_status("S1 write then exit", s, KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
	/* the other ending the same step can report: execve hands off, and the node for it is still made */
	c.n = 0; E(&c, 0xb8, 59, 0, 0, 0, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05);
	s = scan_cb(&c, KGENOME_DIAG_RUN_EMULATE);
	CK(s != NULL);
	if (s) {
		CK(kgenome_diag_scan_count(s) == 1u);
		want_status("S1 execve", s, KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
	/* a program that really does not end is still reported (the control that keeps the bound honest):
	 * jmp $ */
	c.n = 0; sock(&c); E(&c, 0xeb, 0xfe);
	s = scan_cb(&c, KGENOME_DIAG_RUN_EMULATE);
	CK(s != NULL);
	if (s) {
		CK(kgenome_diag_scan_status(s) != KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
}

/* S2 */
static void t_image_status(void)
{
	static struct cb c;
	static struct kgenome_obj o;
	struct kgenome_diag_scan *s;
	struct kgenome_budget bud;

	c.n = 0; sock(&c); mov_rdi_rax(&c); write_sys(&c); exit_sys(&c);
	/* the entry is past the bytes the file holds: there is nothing to run, and that is the input's */
	s = scan_img(elf64(img, &c, 0x400078u + 0x8000u), KGENOME_DIAG_RUN_EMULATE, NULL, 0, &o);
	CK(s != NULL);
	if (s) {
		want_status("S2 entry past the file", s, KGENOME_BAD_INPUT);
		kgenome_diag_scan_free(s);
	}
	/* the caller's memory allowance is too small for the image: that is the budget's */
	memset(&bud, 0, sizeof bud);
	bud.max_bytes = 4096;
	s = scan_img(elf64(img, &c, 0), KGENOME_DIAG_RUN_EMULATE, &bud, 0, &o);
	if (s) {
		want_status("S2 allowance too small for the image", s, KGENOME_OVER_BUDGET);
		kgenome_diag_scan_free(s);
	}
}

/* C1: the wrapper levels over a chain, in ascending address order. A wrapper W (the generic syscall
 * function), D functions `call next; ret` and a main that calls the first with mmap's arguments. */
static const uint8_t wrapper[] = {
	0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xca,
	0x4d, 0x89, 0xc2, 0x4d, 0x89, 0xc8, 0x0f, 0x05, 0xc3
};
static const uint8_t margs[] = {
	0xbf, 9, 0, 0, 0, 0xbe, 0, 0, 0, 0, 0xba, 0, 0x10, 0, 0, 0xb9, 7, 0, 0, 0,
	0x41, 0xb8, 0x22, 0, 0, 0, 0x45, 0x31, 0xc9
};
#define CHAIN_PAD 5000u

static unsigned chain_retries(unsigned d, unsigned *allocs, enum kgenome_status *st, const struct kgenome_budget *bud)
{
	static struct cb c;
	const unsigned main_len = (unsigned)sizeof margs + 6u, f0 = main_len, w = f0 + 6u * d + CHAIN_PAD;
	struct kgenome_diag_scan *s;
	uint32_t i, cnt;
	unsigned k;

	c.n = 0;
	emit(&c, margs, (unsigned)sizeof margs);
	call_to(&c, d ? f0 : w);
	ret(&c);
	for (k = 0; k < d; k++) {
		call_to(&c, k + 1u < d ? f0 + 6u * (k + 1u) : w);
		ret(&c);
	}
	for (k = 0; k < CHAIN_PAD; k++)
		E(&c, 0xcc);
	emit(&c, wrapper, (unsigned)sizeof wrapper);
	retry_calls = 0;
	{
		static struct kgenome_obj o;

		s = scan_img(elf64(img, &c, 0), SWEEP, bud, 0, &o);
	}
	*allocs = 0;
	*st = KGENOME_NOMEM;
	if (!s)
		return 0;
	cnt = kgenome_diag_scan_count(s);
	for (i = 0; i < cnt; i++)
		if (kgenome_diag_scan_at(s, i)->cap == KGENOME_NUCLEO_ALLOC_EXEC)
			(*allocs)++;
	*st = kgenome_diag_scan_status(s);
	kgenome_diag_scan_free(s);
	return retry_calls;
}

static void t_chain_work(void)
{
	static const unsigned depth[] = { 250, 500, 1000, 2000 };
	unsigned r[4], k, a;
	enum kgenome_status st;

	for (k = 0; k < 4u; k++) {
		r[k] = chain_retries(depth[k], &a, &st, NULL);
		if (a != 1u || st != KGENOME_OK)
			printf("  depth %u: %u allocation node(s), status %s\n", depth[k], a, kgenome_status_name(st));
		CK(a == 1u);                            /* the answer is the same at every depth */
		CK(st == KGENOME_OK);
	}
	/* The work counter is the number of times the fixpoint asked whether a function could now come out
	 * differently. It is bounded by the dependencies (a few per function), not by depth x functions:
	 * 8 per function is more than any shape here needs, and the old pass-per-level pays depth/2. */
	for (k = 0; k < 4u; k++) {
		if (r[k] > 8u * depth[k])
			printf("  depth %u: %u retry questions\n", depth[k], r[k]);
		CK(r[k] <= 8u * depth[k]);
	}
	/* and it doubles when the depth does (quadratic would quadruple) */
	CK(r[3] <= 3u * r[2] && r[2] <= 3u * r[1]);
	/* THE LIMIT IS THE STEP BUDGET AND IT IS SAID: a chain deeper than the allowance reaches is cut, the scan
	 * answers KGENOME_OVER_BUDGET (never a silent "no node"), and an allowance that covers it finds the node */
	{
		struct kgenome_budget bud;

		memset(&bud, 0, sizeof bud);
		bud.max_steps = 1000;
		(void)chain_retries(1000, &a, &st, &bud);
		CK(st == KGENOME_OVER_BUDGET);
		CK(a == 0u);
		bud.max_steps = 40000;
		(void)chain_retries(1000, &a, &st, &bud);
		CK(st == KGENOME_OK);
		CK(a == 1u);
	}
}


/* A join that cannot be remembered, a third producer, the stack, a jump that nothing branches to, padding. */
static void t_joins(void)
{
	static struct cb c;
	struct kgenome_diag_scan *sc;
	unsigned a, b, d, h, k;

	/* more pending forward branches than the table holds (256): the merge at them is not made, so what is
	 * carried is MAY, and the cut is said (KGENOME_TRUNCATED) - a cap that never deletes the link */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	{
		static unsigned hole[300];

		for (k = 0; k < 300u; k++) {
			test_rcx(&c);
			hole[k] = jz_fwd(&c);
		}
		for (k = 0; k < 300u; k++)
			here(&c, hole[k]);
	}
	write_sys(&c); exit_sys(&c);
	sc = scan_cb(&c, SWEEP);
	CK(sc != NULL);
	if (sc) {
		unsigned m, y;

		write_links(sc, &m, &y);
		if (m != 0 || y != 1)
			printf("  FAIL join table full: PROVEN %u MAY %u, wanted PROVEN 0 MAY 1\n", m, y);
		CK(m == 0 && y == 1);
		want_status("join table full", sc, KGENOME_TRUNCATED);
		kgenome_diag_scan_free(sc);
	}
	/* control: 200 of them fit, the same value reaches the write on every path: PROVEN, status whole */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	{
		static unsigned hole[200];

		for (k = 0; k < 200u; k++) {
			test_rcx(&c);
			hole[k] = jz_fwd(&c);
		}
		for (k = 0; k < 200u; k++)
			here(&c, hole[k]);
	}
	write_sys(&c); exit_sys(&c);
	expect("join table not full", &c, SWEEP, 1, 0);

	/* three producers meet: all three are kept, MAY, and the scan is whole - a register keeps four, as a node
	 * holds four inputs */
	c.n = 0; test_rcx(&c); a = jz_fwd(&c); test_rcx(&c); b = jz_fwd(&c);
	sock(&c); mov_rdi_rax(&c); d = jmp_fwd(&c);
	here(&c, a); sock(&c); mov_rdi_rax(&c); h = jmp_fwd(&c);
	here(&c, b); sock(&c); mov_rdi_rax(&c);
	here(&c, d); here(&c, h);
	write_sys(&c); exit_sys(&c);
	sc = scan_cb(&c, SWEEP);
	CK(sc != NULL);
	if (sc) {
		unsigned m, y;

		write_links(sc, &m, &y);
		if (m != 0 || y != 3)
			printf("  FAIL three producers: PROVEN %u MAY %u, wanted PROVEN 0 MAY 3\n", m, y);
		CK(m == 0 && y == 3);
		want_status("three producers", sc, KGENOME_OK);
		kgenome_diag_scan_free(sc);
	}
	/* five: four are kept and the fifth is dropped, and said */
	{
		static unsigned hole[4], out[4];

		c.n = 0;
		for (k = 0; k < 4u; k++) {
			test_rcx(&c);
			hole[k] = jz_fwd(&c);
		}
		sock(&c); mov_rdi_rax(&c);
		for (k = 0; k < 4u; k++) {
			out[k] = jmp_fwd(&c);
			here(&c, hole[k]);
			sock(&c); mov_rdi_rax(&c);
		}
		for (k = 0; k < 4u; k++)
			here(&c, out[k]);
		write_sys(&c); exit_sys(&c);
		sc = scan_cb(&c, SWEEP);
		CK(sc != NULL);
		if (sc) {
			unsigned m, y;

			write_links(sc, &m, &y);
			if (m != 0 || y != 4)
				printf("  FAIL five producers: PROVEN %u MAY %u, wanted PROVEN 0 MAY 4\n", m, y);
			CK(m == 0 && y == 4);
			want_status("five producers", sc, KGENOME_TRUNCATED);
			kgenome_diag_scan_free(sc);
		}
	}

	/* the stack: a descriptor pushed before a branch and popped after the join keeps its link on both paths */
	c.n = 0; sock(&c); E(&c, 0x50); test_rcx(&c); a = jz_fwd(&c); E(&c, 0x48, 0xff, 0xc3); here(&c, a);
	E(&c, 0x5f); write_sys(&c); exit_sys(&c);
	expect("stack slot across a join", &c, SWEEP, 1, 0);
	/* an arm that pushes more than the other: what the longer path pushed is not on the shorter one */
	c.n = 0; sock(&c); E(&c, 0x50); test_rcx(&c); a = jz_fwd(&c); E(&c, 0x50); here(&c, a);
	E(&c, 0x5f); write_sys(&c); exit_sys(&c);
	expect("stack slot, uneven arms", &c, SWEEP, 0, 1);
	/* the walk's own slot with no join at all is forgotten at a ret */
	c.n = 0; sock(&c); E(&c, 0x50); ret(&c); pad(&c, 8); E(&c, 0x5f); write_sys(&c); exit_sys(&c);
	expect("stack slot across a ret", &c, SWEEP, 0, 0);

	/* a jmp that nothing branches to: the code after it is reached by a later jump (a rotated loop, a
	 * jmp/call/pop), so the link stays and is MAY */
	c.n = 0; sock(&c); mov_rdi_rax(&c); a = jmp_fwd(&c);
	h = c.n; write_sys(&c); exit_sys(&c);
	here(&c, a); E(&c, 0xe9, 0, 0, 0, 0);
	p32(c.b, c.n - 4u, (uint32_t)(h - c.n));
	expect("jmp, then code only a later jump reaches", &c, SWEEP, 0, 1);
	/* padding between a ret and a branch target is not code: the join is still the way in */
	c.n = 0; sock(&c); mov_rdi_rax(&c); test_rcx(&c); a = jz_fwd(&c); ret(&c); pad(&c, 9); here(&c, a);
	write_sys(&c); exit_sys(&c);
	expect("padding between a ret and its join", &c, SWEEP, 1, 0);
	/* an empty path joins a producer: MAY (the path round has no such value) - the jz is BEFORE the socket */
	c.n = 0; test_rcx(&c); a = jz_fwd(&c); sock(&c); mov_rdi_rax(&c); ret(&c); here(&c, a);
	write_sys(&c); exit_sys(&c);
	expect("a producer behind a ret, reached only by the jump", &c, SWEEP, 0, 0);
}

/* What a callee is read for: the answers are remembered, a callee outside the region or past the bound is
 * not known (MAY), a register pushed and popped back is not written, a callee that pops its return
 * address is the get-pc idiom. */
static void t_callee(void)
{
	static struct cb c;
	unsigned g, h, h2, k;

	/* the same callee twice: one reading */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	h = c.n; E(&c, 0xe8, 0, 0, 0, 0); h2 = c.n; E(&c, 0xe8, 0, 0, 0, 0);
	write_sys(&c); exit_sys(&c);
	g = c.n; ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	p32(c.b, h2 + 1u, (uint32_t)(g - (h2 + 5u)));
	expect("callee called twice", &c, SWEEP, 1, 0);
	/* a callee that saves rdi and restores it */
	c.n = 0; sock(&c); mov_rdi_rax(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c); exit_sys(&c);
	g = c.n; E(&c, 0x57, 0x31, 0xff, 0x5f); ret(&c);          /* push rdi; xor edi,edi; pop rdi; ret */
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("callee restores rdi", &c, SWEEP, 1, 0);
	/* a callee that begins by popping its return address: nothing is called */
	c.n = 0; sock(&c); mov_rdi_rax(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c); exit_sys(&c);
	g = c.n; E(&c, 0x59, 0x31, 0xff); ret(&c);                /* pop rcx; xor edi,edi; ret */
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("callee that pops its return address", &c, SWEEP, 1, 0);
	/* a callee longer than the reading bound with no ret in it: not known */
	c.n = 0; sock(&c); mov_rdi_rax(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c); exit_sys(&c);
	g = c.n; for (k = 0; k < 100u; k++) E(&c, 0x90); ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("callee past the reading bound", &c, SWEEP, 0, 1);
	/* a callee that branches: not known */
	c.n = 0; sock(&c); mov_rdi_rax(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c); exit_sys(&c);
	g = c.n; test_rcx(&c); E(&c, 0x74, 0x00); ret(&c);        /* test rcx,rcx; jz +0; ret */
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("callee that branches", &c, SWEEP, 0, 1);
	/* a callee outside the object: not known */
	c.n = 0; sock(&c); mov_rdi_rax(&c); E(&c, 0xe8, 0x00, 0x00, 0x10, 0x00); write_sys(&c); exit_sys(&c);
	expect("callee outside the region", &c, SWEEP, 0, 1);
	/* a hundred callees (more than the table that remembers them has places), every other one writes rdi: each
	 * call is judged by its own callee, whichever slot it lands in */
	{
		static unsigned at[100];
		unsigned n_ok = 0;
		struct kgenome_diag_scan *sc;

		c.n = 0;
		for (k = 0; k < 100u; k++) {
			sock(&c); mov_rdi_rax(&c); at[k] = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c);
		}
		exit_sys(&c);
		for (k = 0; k < 100u; k++) {
			const unsigned f = c.n;

			if (k % 2u)
				E(&c, 0x31, 0xff);
			ret(&c);
			p32(c.b, at[k] + 1u, (uint32_t)(f - (at[k] + 5u)));
		}
		sc = scan_cb(&c, SWEEP);
		CK(sc != NULL);
		if (sc) {
			unsigned m, y;

			write_links(sc, &m, &y);
			n_ok = m;
			if (m != 50u || y != 0u)
				printf("  FAIL a hundred callees: PROVEN %u MAY %u, wanted PROVEN 50 MAY 0\n", m, y);
			CK(m == 50u && y == 0u);
			kgenome_diag_scan_free(sc);
		}
		(void)n_ok;
	}
	/* a callee in code that does not decode */
	c.n = 0; sock(&c); mov_rdi_rax(&c); h = c.n; E(&c, 0xe8, 0, 0, 0, 0); write_sys(&c); exit_sys(&c);
	g = c.n; E(&c, 0x06, 0x06, 0x06);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect("callee that does not decode", &c, SWEEP, 0, 1);
}

/* A function that meets more call targets than a record holds is asked again after every addition: F calls
 * seven functions that are not wrappers, then G; G is a wrapper only once it has been asked (it is after F in
 * the order), so F is asked a second time. */
static void t_more(void)
{
	static struct cb c;
	/* F: keep the six parameters in callee-saved registers, call six functions that only return, put the
	 * parameters back and call G. G is the seventh target F's first walk meets, and is not yet a wrapper. */
	static const uint8_t save[] = { 0x48, 0x89, 0xfb, 0x48, 0x89, 0xf5, 0x49, 0x89, 0xd4, 0x49, 0x89, 0xcd,
					0x4d, 0x89, 0xc6, 0x4d, 0x89, 0xcf };
	static const uint8_t back[] = { 0x48, 0x89, 0xdf, 0x48, 0x89, 0xee, 0x4c, 0x89, 0xe2, 0x4c, 0x89, 0xe9,
					0x4d, 0x89, 0xf0, 0x4d, 0x89, 0xf9 };
	const unsigned main_len = (unsigned)sizeof margs + 6u, f = main_len;
	const unsigned e0 = f + (unsigned)sizeof save + 6u * 5u + (unsigned)sizeof back + 5u + 1u;
	const unsigned g = e0 + 6u, w = g + 6u + CHAIN_PAD;
	unsigned k;
	struct kgenome_diag_scan *s;
	uint32_t i, cnt, allocs = 0;

	c.n = 0;
	emit(&c, margs, (unsigned)sizeof margs);
	call_to(&c, f);
	ret(&c);
	emit(&c, save, (unsigned)sizeof save);
	for (k = 0; k < 6u; k++)
		call_to(&c, e0 + k);
	emit(&c, back, (unsigned)sizeof back);
	call_to(&c, g);
	ret(&c);
	for (k = 0; k < 6u; k++)
		ret(&c);
	call_to(&c, w);
	ret(&c);
	for (k = 0; k < CHAIN_PAD; k++)
		E(&c, 0xcc);
	emit(&c, wrapper, (unsigned)sizeof wrapper);
	s = scan_cb(&c, SWEEP);
	CK(s != NULL);
	if (!s)
		return;
	cnt = kgenome_diag_scan_count(s);
	for (i = 0; i < cnt; i++)
		if (kgenome_diag_scan_at(s, i)->cap == KGENOME_NUCLEO_ALLOC_EXEC)
			allocs++;
	if (allocs != 1u) {
		for (i = 0; i < cnt; i++)
			printf("   node %u at %#llx cap %s bits %#x\n", i, (unsigned long long)kgenome_diag_scan_at(s, i)->at,
			       kgenome_nucleo_cap_name(kgenome_diag_scan_at(s, i)->cap), kgenome_diag_scan_at(s, i)->bits);
	}
	CK(allocs == 1u);
	want_status("a function that meets more than a record holds", s, KGENOME_OK);
	kgenome_diag_scan_free(s);
}

/* The run and the walk find the same link: the run's proof is kept (the walk's MAY becomes PROVEN). */
static void t_proof_kept(void)
{
	static struct cb c;
	unsigned a, b, m, y;
	struct kgenome_diag_scan *s;

	c.n = 0;
	E(&c, 0x59);
	test_rcx(&c);
	a = jz_fwd(&c);
	sock(&c); mov_rdi_rax(&c);
	b = jmp_fwd(&c);
	here(&c, a);
	sock(&c); mov_rdi_rax(&c);
	here(&c, b);
	write_sys(&c); exit_sys(&c);
	s = scan_cb(&c, SWEEP | KGENOME_DIAG_RUN_EMULATE);
	CK(s != NULL);
	if (!s)
		return;
	write_links(s, &m, &y);
	/* the run took the arm rcx (argc) sends it down: that link is demonstrated; the other is only a path */
	if (m != 1 || y != 1)
		printf("  FAIL run + walk: PROVEN %u MAY %u, wanted PROVEN 1 MAY 1\n", m, y);
	CK(m == 1 && y == 1);
	kgenome_diag_scan_free(s);
}


/* The same rules on the other machines the sweep reads: the registers a callee may overwrite are the ABI's. */
static void w32(struct cb *c, uint32_t v)
{
	uint8_t b[4];

	p32(b, 0, v);
	emit(c, b, 4);
}

static void expect_elf32(const char *what, const struct cb *c, unsigned must, unsigned may)
{
	static struct kgenome_obj o;
	struct kgenome_diag_scan *s = scan_img(elf32(img, c), SWEEP, NULL, 0, &o);
	unsigned m = 0, y = 0;

	if (!s) {
		printf("  FAIL %s: no scan\n", what);
		hk_fails++;
		return;
	}
	write_links(s, &m, &y);
	if (m != must || y != may) {
		printf("  FAIL %s: PROVEN %u MAY %u, wanted PROVEN %u MAY %u\n", what, m, y, must, may);
		hk_fails++;
	}
	kgenome_diag_scan_free(s);
}

static void t_arm(void)
{
	static struct cb c;
	unsigned h, g;

	/* AArch64: socket(2, 1, 0); x0 holds the descriptor; bl g; write(x0 ...) */
	elf_machine = 0xb7;
	c.n = 0;
	w32(&c, 0xd28018c8u); w32(&c, 0xd2800040u); w32(&c, 0xd2800021u); w32(&c, 0xd2800002u); w32(&c, 0xd4000001u);
	w32(&c, 0xaa0003f3u);                           /* mov x19, x0 */
	h = c.n; w32(&c, 0x94000000u);                  /* bl g */
	w32(&c, 0xd2800808u); w32(&c, 0xd4000001u);     /* write */
	w32(&c, 0xd2800ba8u); w32(&c, 0xd4000001u);     /* exit */
	g = c.n; w32(&c, 0xd2800000u); w32(&c, 0xd65f03c0u);    /* g: mov x0, #0; ret */
	p32(c.b, h, 0x94000000u | ((g - h) / 4u));
	expect("arm64: callee writes x0", &c, SWEEP, 0, 0);
	c.n = 0;
	w32(&c, 0xd28018c8u); w32(&c, 0xd2800040u); w32(&c, 0xd2800021u); w32(&c, 0xd2800002u); w32(&c, 0xd4000001u);
	h = c.n; w32(&c, 0x94000000u);
	w32(&c, 0xd2800808u); w32(&c, 0xd4000001u);
	w32(&c, 0xd2800ba8u); w32(&c, 0xd4000001u);
	g = c.n; w32(&c, 0xd65f03c0u);                  /* g: ret */
	p32(c.b, h, 0x94000000u | ((g - h) / 4u));
	expect("arm64: control, callee only returns", &c, SWEEP, 1, 0);
	elf_machine = 0x3e;

	/* ARM: socket(2, 1, 0) is 281 (movw r7); r0 holds the descriptor; bl g; write(r0 ...) is 4 */
	c.n = 0;
	w32(&c, 0xe3007119u); w32(&c, 0xe3a00002u); w32(&c, 0xe3a01001u); w32(&c, 0xe3a02000u); w32(&c, 0xef000000u);
	h = c.n; w32(&c, 0xeb000000u);
	w32(&c, 0xe3a07004u); w32(&c, 0xef000000u);
	w32(&c, 0xe3a07001u); w32(&c, 0xef000000u);
	g = c.n; w32(&c, 0xe3a00000u); w32(&c, 0xe12fff1eu);    /* g: mov r0, #0; bx lr */
	p32(c.b, h, 0xeb000000u | (((g - h) / 4u) - 2u));
	expect_elf32("arm: callee writes r0", &c, 0, 0);
	c.n = 0;
	w32(&c, 0xe3007119u); w32(&c, 0xe3a00002u); w32(&c, 0xe3a01001u); w32(&c, 0xe3a02000u); w32(&c, 0xef000000u);
	h = c.n; w32(&c, 0xeb000000u);
	w32(&c, 0xe3a07004u); w32(&c, 0xef000000u);
	w32(&c, 0xe3a07001u); w32(&c, 0xef000000u);
	g = c.n; w32(&c, 0xe12fff1eu);                  /* g: bx lr */
	p32(c.b, h, 0xeb000000u | (((g - h) / 4u) - 2u));
	expect_elf32("arm: control, callee only returns", &c, 1, 0);
}

/* The allowance is too small for the table of pending joins: the walk cannot remember the other path, so it is the
 * straight line it was, and the refusal is the ledger's (over-budget). The link is never lost; a scan that says OK
 * remembered the join and says MAY. */
static void t_small_allowance(void)
{
	static struct cb c;
	static struct kgenome_obj o;
	struct kgenome_diag_scan *sc;
	struct kgenome_budget bud;
	unsigned a, m, y, k;
	int refused = 0, whole = 0;

	c.n = 0; test_rcx(&c); a = jz_fwd(&c); sock(&c); mov_rdi_rax(&c); here(&c, a); write_sys(&c); exit_sys(&c);
	for (k = 1; k <= 24u; k++) {
		memset(&bud, 0, sizeof bud);
		bud.max_bytes = 16384u * k;
		sc = scan_img(elf64(img, &c, 0), SWEEP, &bud, 0, &o);
		if (!sc)
			continue;
		write_links(sc, &m, &y);
		if (m + y != 1u || (kgenome_diag_scan_status(sc) == KGENOME_OK && m != 0u)) {
			printf("  FAIL allowance %llu: PROVEN %u MAY %u (status %s)\n", (unsigned long long)bud.max_bytes, m, y,
			       kgenome_status_name(kgenome_diag_scan_status(sc)));
			hk_fails++;
		}
		refused |= kgenome_diag_scan_status(sc) == KGENOME_OVER_BUDGET;
		whole |= kgenome_diag_scan_status(sc) == KGENOME_OK && y == 1u;
		kgenome_diag_scan_free(sc);
	}
	CK(refused && whole);                           /* the sweep of allowances crossed the boundary both ways */
}

/* A callee whose first byte is in the headers of the object: inside the file, outside the code region. */
static void t_headers_callee(void)
{
	static struct cb c;

	c.n = 0; sock(&c); mov_rdi_rax(&c);
	/* call to file offset 0x10: relative to the end of this call, which is at code offset n + 5 (file 0x78 + n + 5) */
	c.b[c.n] = 0xe8;
	p32(c.b, c.n + 1u, (uint32_t)(0x10 - (0x78 + c.n + 5u)));
	c.n += 5u;
	write_sys(&c); exit_sys(&c);
	expect("callee in the headers", &c, SWEEP, 0, 1);
}

/* A join reached with a second pair of producers: after one join the register holds two, and a third path
 * brings a third; all three are MAY. */
static void t_merge_alt(void)
{
	static struct cb c;
	unsigned a, b, d;

	c.n = 0;
	test_rcx(&c); a = jz_fwd(&c);
	sock(&c); mov_rdi_rax(&c); b = jmp_fwd(&c);
	here(&c, a); sock(&c); mov_rdi_rax(&c);
	here(&c, b);                                    /* rdi: two producers */
	test_rcx(&c); d = jz_fwd(&c);
	sock(&c); mov_rdi_rax(&c);                      /* a third on this arm */
	here(&c, d);
	write_sys(&c); exit_sys(&c);
	expect("two producers, then a third", &c, SWEEP, 0, 3);
}

/* The levels of the wrapper fixpoint: a function that meets a wrapper found EARLIER IN THE SAME LEVEL is asked in
 * that level. X0 calls X2, X1 calls X0, X2 calls W: the first pass finds X2, the second X0 and then X1. */
static void t_levels_in_order(void)
{
	static struct cb c;
	const unsigned main_len = (unsigned)sizeof margs + 6u, x0 = main_len, x1 = x0 + 6u, x2 = x1 + 6u,
		       w = x2 + 6u + CHAIN_PAD;
	struct kgenome_diag_scan *s;
	uint32_t i, cnt, allocs = 0;
	unsigned k;

	c.n = 0;
	emit(&c, margs, (unsigned)sizeof margs);
	call_to(&c, x1);                                /* main calls X1 */
	ret(&c);
	call_to(&c, x2); ret(&c);                       /* X0 */
	call_to(&c, x0); ret(&c);                       /* X1 */
	call_to(&c, w); ret(&c);                        /* X2 */
	for (k = 0; k < CHAIN_PAD; k++)
		E(&c, 0xcc);
	emit(&c, wrapper, (unsigned)sizeof wrapper);
	s = scan_cb(&c, SWEEP);
	CK(s != NULL);
	if (!s)
		return;
	cnt = kgenome_diag_scan_count(s);
	for (i = 0; i < cnt; i++)
		if (kgenome_diag_scan_at(s, i)->cap == KGENOME_NUCLEO_ALLOC_EXEC)
			allocs++;
	CK(allocs == 1u);
	want_status("levels in order", s, KGENOME_OK);
	kgenome_diag_scan_free(s);
}

/* The step budget at every size around the cost of a chain: never a silent "no node" - a chain that was not
 * followed says OVER_BUDGET, and the answer is the same node once the allowance covers it. */
static void t_budget_sweep(void)
{
	unsigned steps, allocs;
	enum kgenome_status st;
	struct kgenome_budget bud;
	unsigned cut = 0, whole = 0;

	for (steps = 20; steps <= 2000; steps += 20) {
		memset(&bud, 0, sizeof bud);
		bud.max_steps = steps;
		(void)chain_retries(60, &allocs, &st, &bud);
		if (allocs == 0u && st != KGENOME_OVER_BUDGET) {
			printf("  FAIL allowance %u steps: no node and status %s\n", steps, kgenome_status_name(st));
			hk_fails++;
		}
		if (allocs == 1u && st != KGENOME_OK) {
			printf("  FAIL allowance %u steps: the node and status %s\n", steps, kgenome_status_name(st));
			hk_fails++;
		}
		cut += allocs == 0u;
		whole += allocs == 1u;
	}
	CK(cut > 0 && whole > 0);                       /* the sweep crossed the boundary both ways */
}

/* U1: the lineage over programs with branches and no stack slot at all. */
static void t_null_args(void)
{
	static struct cb c;
	unsigned a, b, run;

	for (run = 0; run < 3u; run++) {
		static const unsigned runs[] = { SWEEP | KGENOME_DIAG_RUN_LINEAGE,
						 SWEEP | KGENOME_DIAG_RUN_EMULATE | KGENOME_DIAG_RUN_LINEAGE,
						 KGENOME_DIAG_RUN_ALL };
		struct kgenome_diag_scan *s;

		c.n = 0;
		E(&c, 0x59);
		test_rcx(&c);
		a = jz_fwd(&c);
		sock(&c); mov_rdi_rax(&c);
		b = jmp_fwd(&c);
		here(&c, a);
		sock(&c); mov_rdi_rax(&c);
		here(&c, b);
		write_sys(&c); exit_sys(&c);
		null_mem = 0;
		s = scan_cb(&c, runs[run]);
		CK(s != NULL);
		if (s)
			kgenome_diag_scan_free(s);
		if (null_mem)
			printf("  run %#x: %u call(s) with a NULL argument\n", runs[run], null_mem);
		CK(null_mem == 0);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_ret();
	t_call();
	t_arms();
	t_partial();
	t_fanin();
	t_exit_status();
	t_image_status();
	t_joins();
	t_callee();
	t_more();
	t_proof_kept();
	t_arm();
	t_small_allowance();
	t_headers_callee();
	t_merge_alt();
	t_levels_in_order();
	t_chain_work();
	t_budget_sweep();
	t_null_args();
	printf("diag_graph_bin: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
