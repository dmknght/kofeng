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
#include <phenotype/diag_private.h>

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

/* Every link names a node of the scan: a second pass over a loop merges the first pass's node numbers, and a link
 * to a number it did not make would point out of the array. */
static void links_valid(const char *what, const struct kgenome_diag_scan *s)
{
	uint32_t i, cnt = kgenome_diag_scan_count(s);
	unsigned k;

	for (i = 0; i < cnt; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		for (k = 0; k < h->n_in; k++)
			if (h->in[k].from >= cnt && h->in[k].from != KGENOME_DIAG_ORG_STACK) {
				printf("  FAIL %s: node %u has a link from node %u of %u\n", what, i, h->in[k].from, cnt);
				hk_fails++;
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
	links_valid(what, s);
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

/* ====================================================================================================
 * THE SECOND ROUND: X1, X2, X3, X5, X8 (found while fixing W1-W6, not fixed there).
 *
 *   X1   a CALL did nothing to the constant map, so a constant the callee overwrote was still "known"
 *        afterwards: `mov edx,7; call g; ...; mov eax,10; syscall` with `g: xor edx,edx; ret` was a node
 *        that makes memory executable. The map-level cases are in cell_call_clobber.c; here the same
 *        defect is seen through the sweep (a false capability), and the controls keep what the ABI keeps.
 *   X2   the symbol route (a relocatable object, diag_sym.c) had W3/W5: the decoder gives CALL and RET no
 *        written register, so an origin survived any call that was not itself a named capability, and a
 *        `ret` in the middle of a function changed nothing.
 *   X3   back edges were not merged (a value written in a loop body and read at the top of the next pass
 *        kept the first producer as PROVEN), and a tail `jmp` into another function was treated like the
 *        jmp/call/pop idiom (the code after it, which is the next function, kept every origin as MAY).
 *   X5   the stack ring counted push and pop and nothing else: `add esp,N`, `sub esp,N`, `leave`,
 *        `lea esp,[ebp-N]` moved the real stack and not the ring, so a pop took the wrong slot (the link
 *        was lost) and a cdecl call in a loop grew the depth until the ring overflowed (TRUNCATED).
 *   X8   rel_image_fail (the relocatable image could not be built) had no test: it needs an ET_REL.
 *
 * Why the old tests missed them: (X1) no case put a real call between the write and the read of a constant
 * (a); (X2) the symbol-route tests (relcalls_shared, diag_nodes, ko_anomalies) check which nodes there are
 * and that the god_mode shape links, never a link across a call that is not a node (c); (X3) every sweep
 * test was straight-line or forward-branching; no program had a backward branch with a carried origin (b),
 * and no program had a function table, so a tail jump had no function to leave (a); (X5) the ring was only
 * ever fed push and pop (b); (X8) line never executed (a).
 *
 * Counted, not timed: the back-edge work is bounded by the number of instructions the sweep decodes
 * (kgenome_cell_next, wrapped at link time) and a cap that fires says so (KGENOME_TRUNCATED).
 */

static unsigned cell_next_calls;        /* the instructions the sweep decoded */

int __real_kgenome_cell_next(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
			     struct kgenome_cell_insn *out);
int __wrap_kgenome_cell_next(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
			     struct kgenome_cell_insn *out);
int __wrap_kgenome_cell_next(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
			     struct kgenome_cell_insn *out)
{
	cell_next_calls++;
	return __real_kgenome_cell_next(k, sp, out);
}

static unsigned funcs_calls;            /* the function table asked for (the sweep asks only where a symbol table names functions) */

const struct kgenome_func_set *__real_kgenome_diag_funcs(struct kgenome_diag_scan *s, const struct kgenome_obj *obj);
const struct kgenome_func_set *__wrap_kgenome_diag_funcs(struct kgenome_diag_scan *s, const struct kgenome_obj *obj);
const struct kgenome_func_set *__wrap_kgenome_diag_funcs(struct kgenome_diag_scan *s, const struct kgenome_obj *obj)
{
	funcs_calls++;
	return __real_kgenome_diag_funcs(s, obj);
}

static void p16(uint8_t *b, unsigned at, unsigned v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}

static unsigned al8(unsigned v)
{
	return (v + 7u) & ~7u;
}

static unsigned count_cap(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t i, cnt = kgenome_diag_scan_count(s);
	unsigned n = 0;

	for (i = 0; i < cnt; i++)
		if (kgenome_diag_scan_at(s, i)->cap == cap)
			n++;
	return n;
}

/* The links from a node of capability `from` into a node of capability `to`: PROVEN, MAY. */
static void links_cap(const struct kgenome_diag_scan *s, uint16_t from, uint16_t to, unsigned *must, unsigned *may)
{
	uint32_t i, cnt = kgenome_diag_scan_count(s);
	unsigned k;

	*must = *may = 0;
	for (i = 0; i < cnt; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		if (h->cap != to)
			continue;
		for (k = 0; k < h->n_in; k++) {
			const struct kgenome_diag_hit *p = h->in[k].from < cnt ? kgenome_diag_scan_at(s, h->in[k].from) : NULL;

			if (!p || p->cap != from)
				continue;
			if (h->in[k].how == KGENOME_DIAG_LINK_MAY)
				(*may)++;
			else
				(*must)++;
		}
	}
}

static void expect_cap(const char *what, const struct cb *c, unsigned run, uint16_t cap, unsigned want)
{
	struct kgenome_diag_scan *s = scan_cb(c, run);
	unsigned n;

	if (!s) {
		printf("  FAIL %s: no scan\n", what);
		hk_fails++;
		return;
	}
	n = count_cap(s, cap);
	if (n != want) {
		printf("  FAIL %s: %u node(s) of that capability, wanted %u\n", what, n, want);
		hk_fails++;
	}
	kgenome_diag_scan_free(s);
}

/* the same as expect(), with the status too, and a range for the MAY count (a merge may keep a second producer) */
static void expect_x(const char *what, const struct cb *c, unsigned run, unsigned must, unsigned may_lo, unsigned may_hi,
		     enum kgenome_status st)
{
	struct kgenome_diag_scan *s = scan_cb(c, run);
	unsigned m = 0, y = 0;

	if (!s) {
		printf("  FAIL %s: no scan\n", what);
		hk_fails++;
		return;
	}
	write_links(s, &m, &y);
	if (m != must || y < may_lo || y > may_hi) {
		printf("  FAIL %s: PROVEN %u MAY %u, wanted PROVEN %u MAY %u..%u\n", what, m, y, must, may_lo, may_hi);
		hk_fails++;
	}
	if (kgenome_diag_scan_status(s) != st) {
		printf("  FAIL %s: status %s, wanted %s\n", what, kgenome_status_name(kgenome_diag_scan_status(s)),
		       kgenome_status_name(st));
		hk_fails++;
	}
	links_valid(what, s);
	kgenome_diag_scan_free(s);
}

/* An ELF32 with the machine named (3: i386); the code and the entry are at +0x54. */
static uint64_t elf32m(uint8_t *b, const struct cb *c, unsigned machine)
{
	const uint64_t n = elf32(b, c);

	p16(b, 18, machine);
	return n;
}

static struct kgenome_diag_scan *scan_cb32(const struct cb *c, unsigned run)
{
	static struct kgenome_obj o;

	return scan_img(elf32m(img, c, 3), run, NULL, 0, &o);
}

/* ---- X1 ------------------------------------------------------------------------------------------ */

static void t_x1(void)
{
	static struct cb c;
	struct kgenome_diag_scan *s;
	unsigned g, h;

	/* mprotect(0x401000, 0x1000, 7) with the protection written BEFORE a call whose callee zeroes it */
	c.n = 0;
	E(&c, 0xba, 7, 0, 0, 0);                        /* mov edx,7 */
	h = c.n; E(&c, 0xe8, 0, 0, 0, 0);               /* call g */
	E(&c, 0xbf, 0, 0x10, 0x40, 0);                  /* mov edi,0x401000 */
	E(&c, 0xbe, 0, 0x10, 0, 0);                     /* mov esi,0x1000 */
	E(&c, 0xb8, 10, 0, 0, 0, 0x0f, 0x05);           /* mov eax,10; syscall */
	exit_sys(&c);
	g = c.n; E(&c, 0x31, 0xd2); ret(&c);            /* g: xor edx,edx; ret */
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect_cap("X1 callee zeroes edx: no PROT_EXEC", &c, SWEEP, KGENOME_NUCLEO_ALLOC_EXEC, 0);
	/* the limit, written down: a callee that only returns gets the same answer, because the rule is the
	 * calling convention's and not a reading of the callee (edx is caller-saved) */
	c.b[g] = 0xc3; c.n = g + 1u;
	expect_cap("X1 limit: callee that only returns, edx is the callee's by the ABI", &c, SWEEP, KGENOME_NUCLEO_ALLOC_EXEC, 0);

	/* control: the protection written after the call is the program's */
	c.n = 0;
	h = c.n; E(&c, 0xe8, 0, 0, 0, 0);
	E(&c, 0xba, 7, 0, 0, 0);
	E(&c, 0xbf, 0, 0x10, 0x40, 0);
	E(&c, 0xbe, 0, 0x10, 0, 0);
	E(&c, 0xb8, 10, 0, 0, 0, 0x0f, 0x05);
	exit_sys(&c);
	g = c.n; E(&c, 0x31, 0xd2); ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect_cap("X1 control: protection set after the call", &c, SWEEP, KGENOME_NUCLEO_ALLOC_EXEC, 1);

	/* the number: execve's, loaded before a call whose callee overwrites eax (the return value) */
	c.n = 0;
	E(&c, 0xb8, 59, 0, 0, 0);
	h = c.n; E(&c, 0xe8, 0, 0, 0, 0);
	E(&c, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05);
	exit_sys(&c);
	g = c.n; E(&c, 0x31, 0xc0); ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect_cap("X1 callee overwrites eax: no execve", &c, SWEEP, KGENOME_NUCLEO_EXEC_IMAGE, 0);
	c.n = 0;
	h = c.n; E(&c, 0xe8, 0, 0, 0, 0);
	E(&c, 0xb8, 59, 0, 0, 0);
	E(&c, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xd2, 0x0f, 0x05);
	exit_sys(&c);
	g = c.n; E(&c, 0x31, 0xc0); ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	expect_cap("X1 control: execve's number after the call", &c, SWEEP, KGENOME_NUCLEO_EXEC_IMAGE, 1);

	/* i386: ebx is callee-saved, so socketcall's sub-call written before the call is still the program's */
	c.n = 0;
	E(&c, 0xbb, 1, 0, 0, 0);                        /* mov ebx,1 (SYS_SOCKET) */
	h = c.n; E(&c, 0xe8, 0, 0, 0, 0);               /* call g */
	E(&c, 0xb8, 102, 0, 0, 0);                      /* mov eax,102 (socketcall) */
	E(&c, 0xb9, 0, 0, 0, 0);                        /* mov ecx,0 */
	E(&c, 0xcd, 0x80);
	E(&c, 0xb8, 1, 0, 0, 0, 0xcd, 0x80);
	g = c.n; ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	s = scan_cb32(&c, SWEEP);
	CK(s != NULL);
	if (s) {
		if (count_cap(s, KGENOME_NUCLEO_NET_OPEN) != 1u) {
			printf("  FAIL X1 control, i386 ebx across a call: %u net-open node(s), wanted 1\n",
			       count_cap(s, KGENOME_NUCLEO_NET_OPEN));
			hk_fails++;
		}
		kgenome_diag_scan_free(s);
	}
	/* and the number, eax, is not: written before the call it is the callee's */
	c.n = 0;
	E(&c, 0xb8, 102, 0, 0, 0);
	h = c.n; E(&c, 0xe8, 0, 0, 0, 0);
	E(&c, 0xbb, 1, 0, 0, 0);
	E(&c, 0xb9, 0, 0, 0, 0);
	E(&c, 0xcd, 0x80);
	E(&c, 0xb8, 1, 0, 0, 0, 0xcd, 0x80);
	g = c.n; ret(&c);
	p32(c.b, h + 1u, (uint32_t)(g - (h + 5u)));
	s = scan_cb32(&c, SWEEP);
	CK(s != NULL);
	if (s) {
		if (count_cap(s, KGENOME_NUCLEO_NET_OPEN) != 0u) {
			printf("  FAIL X1 i386 eax across a call: %u net-open node(s), wanted 0\n",
			       count_cap(s, KGENOME_NUCLEO_NET_OPEN));
			hk_fails++;
		}
		kgenome_diag_scan_free(s);
	}
}

/* ---- X2: an ET_REL (a kernel module's shape) ------------------------------------------------------ */

struct rsym {
	const char *name;
	unsigned    off, len;       /* a function this object defines (len != 0), or an import */
};
struct rcall {
	unsigned at;                /* the offset of the call's 4-byte displacement */
	unsigned sym;               /* index in the rsym list */
};

/* One .text, its relocations (R_X86_64_PLT32) and a symbol table; returns the file length. */
static uint64_t rel_obj(uint8_t *b, const struct cb *c, const struct rsym *sy, unsigned nsy,
			const struct rcall *rc, unsigned nrc)
{
	static const char shs[] = "\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0";
	char str[512];
	unsigned strn = 1, i, nm[16];
	const unsigned text_off = 0x40, rela_off = al8(text_off + c->n), sym_off = al8(rela_off + nrc * 24u),
		       str_off = sym_off + (nsy + 1u) * 24u;
	unsigned shstr_off, sh_off;
	uint8_t *p;

	str[0] = 0;
	for (i = 0; i < nsy; i++) {
		nm[i] = strn;
		strn += (unsigned)strlen(sy[i].name) + 1u;
		memcpy(str + nm[i], sy[i].name, strlen(sy[i].name) + 1u);
	}
	shstr_off = str_off + strn;
	sh_off = al8(shstr_off + (unsigned)sizeof shs);
	memset(b, 0, sh_off + 6u * 64u);
	memcpy(b, "\177ELF\2\1\1", 7);
	p16(b, 16, 1); p16(b, 18, 62); p32(b, 20, 1);
	p64(b, 40, sh_off);
	p16(b, 52, 64); p16(b, 58, 64); p16(b, 60, 6); p16(b, 62, 5);
	memcpy(b + text_off, c->b, c->n);
	for (i = 0; i < nrc; i++) {
		p = b + rela_off + i * 24u;
		p64(p, 0, rc[i].at);
		p64(p, 8, ((uint64_t)(rc[i].sym + 1u) << 32) | 4u);
		p64(p, 16, (uint64_t)-4);
	}
	for (i = 0; i < nsy; i++) {
		p = b + sym_off + (i + 1u) * 24u;
		p32(p, 0, nm[i]);
		p[4] = 0x12;                                    /* GLOBAL FUNC */
		p16(p, 6, sy[i].len ? 1u : 0u);
		p64(p, 8, sy[i].off);
		p64(p, 16, sy[i].len);
	}
	memcpy(b + str_off, str, strn);
	memcpy(b + shstr_off, shs, sizeof shs);
	p = b + sh_off;
	p32(p + 64, 0, 1); p32(p + 64, 4, 1); p64(p + 64, 8, 6);                        /* .text */
	p64(p + 64, 24, text_off); p64(p + 64, 32, c->n); p64(p + 64, 48, 16);
	p32(p + 128, 0, 7); p32(p + 128, 4, 4); p64(p + 128, 8, 0x40);                  /* .rela.text */
	p64(p + 128, 24, rela_off); p64(p + 128, 32, nrc * 24u); p32(p + 128, 40, 3);
	p32(p + 128, 44, 1); p64(p + 128, 48, 8); p64(p + 128, 56, 24);
	p32(p + 192, 0, 18); p32(p + 192, 4, 2); p64(p + 192, 24, sym_off);             /* .symtab */
	p64(p + 192, 32, (nsy + 1u) * 24u); p32(p + 192, 40, 4);
	p32(p + 192, 44, 1); p64(p + 192, 48, 8); p64(p + 192, 56, 24);
	p32(p + 256, 0, 26); p32(p + 256, 4, 3); p64(p + 256, 24, str_off);             /* .strtab */
	p64(p + 256, 32, strn); p64(p + 256, 48, 1);
	p32(p + 320, 0, 34); p32(p + 320, 4, 3); p64(p + 320, 24, shstr_off);           /* .shstrtab */
	p64(p + 320, 32, sizeof shs); p64(p + 320, 48, 1);
	return sh_off + 6u * 64u;
}

static uint16_t cap_named(const char *name)
{
	return (uint16_t)kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, name);
}

/* A module of one function `fn` (the whole of .text unless `fn_len` says less) calling imports by relocation. */
struct kmod {
	struct cb c;
	struct rsym sy[8];
	unsigned nsy;
	struct rcall rc[8];
	unsigned nrc;
	unsigned fn_len;
};

static void km_start(struct kmod *m)
{
	memset(m, 0, sizeof *m);
	m->sy[0].name = "fn";
	m->nsy = 1;
}

static unsigned km_import(struct kmod *m, const char *name)
{
	unsigned i;

	for (i = 0; i < m->nsy; i++)
		if (!strcmp(m->sy[i].name, name))
			return i;
	m->sy[m->nsy].name = name;
	return m->nsy++;
}

/* `call name` through a relocation: e8 00 00 00 00 */
static void km_call(struct kmod *m, const char *name)
{
	m->rc[m->nrc].at = m->c.n + 1u;
	m->rc[m->nrc].sym = km_import(m, name);
	m->nrc++;
	E(&m->c, 0xe8, 0, 0, 0, 0);
}

static uint64_t km_image(struct kmod *m)
{
	m->sy[0].off = 0;
	m->sy[0].len = m->fn_len ? m->fn_len : m->c.n;
	return rel_obj(img, &m->c, m->sy, m->nsy, m->rc, m->nrc);
}

/* the links from prepare_creds's node into commit_creds's, over the symbol route */
static void km_expect(const char *what, struct kmod *m, unsigned must, unsigned may)
{
	static struct kgenome_obj o;
	struct kgenome_diag_scan *s = scan_img(km_image(m), KGENOME_DIAG_RUN_SYMBOL, NULL, 0, &o);
	unsigned y = 0, n = 0;

	if (!s) {
		printf("  FAIL %s: no scan\n", what);
		hk_fails++;
		return;
	}
	links_cap(s, cap_named("prepare_creds"), cap_named("commit_creds"), &y, &n);
	if (y != must || n != may) {
		printf("  FAIL %s: PROVEN %u MAY %u, wanted PROVEN %u MAY %u\n", what, y, n, must, may);
		hk_fails++;
	}
	kgenome_diag_scan_free(s);
}

static void t_x2(void)
{
	static struct kmod m;
	unsigned h;

	/* control: the god_mode shape, prepare_creds, move, commit_creds */
	km_start(&m);
	km_call(&m, "prepare_creds"); E(&m.c, 0x48, 0x89, 0xc7); km_call(&m, "commit_creds"); ret(&m.c);
	km_expect("X2 control, god_mode shape", &m, 1, 0);

	/* a call to an import that is not a capability, between the producer and the consumer: the callee may
	 * have written rdi, and it is not read, so the link is MAY (the sweep's rule for a callee it does not read) */
	km_start(&m);
	km_call(&m, "prepare_creds"); E(&m.c, 0x48, 0x89, 0xc7); km_call(&m, "my_helper"); km_call(&m, "commit_creds"); ret(&m.c);
	km_expect("X2 import without a capability between", &m, 0, 1);

	/* the same with a named capability in between (it is a node of its own and clobbers the same registers) */
	km_start(&m);
	km_call(&m, "prepare_creds"); E(&m.c, 0x48, 0x89, 0xc7); km_call(&m, "kmalloc"); km_call(&m, "commit_creds"); ret(&m.c);
	km_expect("X2 named capability between", &m, 0, 1);

	/* the register the ABI makes the callee keep: rbx holds the cred across the call */
	km_start(&m);
	km_call(&m, "prepare_creds"); E(&m.c, 0x48, 0x89, 0xc3); km_call(&m, "my_helper");
	E(&m.c, 0x48, 0x89, 0xdf); km_call(&m, "commit_creds"); ret(&m.c);
	km_expect("X2 control, rbx across an import call", &m, 1, 0);

	/* rax is the callee's return value: after an unknown call it is not prepare_creds's result */
	km_start(&m);
	km_call(&m, "prepare_creds"); km_call(&m, "my_helper"); E(&m.c, 0x48, 0x89, 0xc7); km_call(&m, "commit_creds"); ret(&m.c);
	km_expect("X2 rax after an import call", &m, 0, 1);

	/* a call this object resolves by itself (no relocation): the callee is read, as the sweep reads it.
	 * helper writes rdi: the origin is gone. */
	km_start(&m);
	km_call(&m, "prepare_creds"); E(&m.c, 0x48, 0x89, 0xc7);
	h = m.c.n; E(&m.c, 0xe8, 0, 0, 0, 0);
	km_call(&m, "commit_creds"); ret(&m.c);
	m.fn_len = m.c.n;
	{
		unsigned hp = m.c.n;

		E(&m.c, 0x31, 0xff); ret(&m.c);                 /* helper: xor edi,edi; ret */
		p32(m.c.b, h + 1u, (uint32_t)(hp - (h + 5u)));
		m.sy[m.nsy].name = "helper"; m.sy[m.nsy].off = hp; m.sy[m.nsy].len = 3; m.nsy++;
	}
	km_expect("X2 resolved callee writes rdi", &m, 0, 0);
	/* the same callee only returns: the link stands */
	m.c.b[m.fn_len] = 0xc3;
	km_expect("X2 control, resolved callee only returns", &m, 1, 0);

	/* a ret in the middle of the function: what follows it is reached by a branch the route does not model */
	km_start(&m);
	km_call(&m, "prepare_creds"); E(&m.c, 0x48, 0x89, 0xc7); ret(&m.c); km_call(&m, "commit_creds"); ret(&m.c);
	km_expect("X2 code after a ret", &m, 0, 1);
}

/* ---- X5: the stack ring follows the stack pointer ---------------------------------------------- */

static void t_x5(void)
{
	static struct cb c;
	unsigned i;

	/* add rsp,8 gives up a slot: pop rdi then takes the socket the program pushed first */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	E(&c, 0x57, 0x56, 0x48, 0x83, 0xc4, 0x08, 0x5f);        /* push rdi; push rsi; add rsp,8; pop rdi */
	write_sys(&c); exit_sys(&c);
	expect_x("X5 add rsp", &c, SWEEP, 1, 0, 0, KGENOME_OK);

	/* sub then add: the frame is made and given back, the slot below it is untouched */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	E(&c, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x83, 0xc4, 0x20, 0x5f);   /* push rdi; sub rsp,0x20; add rsp,0x20; pop rdi */
	write_sys(&c); exit_sys(&c);
	expect_x("X5 control, sub then add", &c, SWEEP, 1, 0, 0, KGENOME_OK);

	/* leave: rsp goes back to rbp, the two pushes after `mov rbp,rsp` are gone, and rbp is popped */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	E(&c, 0x57, 0x55, 0x48, 0x89, 0xe5, 0x56, 0x51, 0xc9, 0x5f);   /* push rdi; push rbp; mov rbp,rsp; push rsi; push rcx; leave; pop rdi */
	write_sys(&c); exit_sys(&c);
	expect_x("X5 leave", &c, SWEEP, 1, 0, 0, KGENOME_OK);

	/* lea rsp,[rbp-8]: the epilogue of a frame with a callee-saved register below the frame pointer */
	c.n = 0; sock(&c);
	E(&c, 0x48, 0x89, 0xc3);                                        /* mov rbx,rax */
	E(&c, 0x55, 0x48, 0x89, 0xe5, 0x53);                            /* push rbp; mov rbp,rsp; push rbx */
	E(&c, 0x48, 0x83, 0xec, 0x40, 0x51);                            /* sub rsp,0x40; push rcx */
	E(&c, 0x48, 0x8d, 0x65, 0xf8, 0x5b, 0x5d);                      /* lea rsp,[rbp-8]; pop rbx; pop rbp */
	E(&c, 0x48, 0x89, 0xdf);                                        /* mov rdi,rbx */
	write_sys(&c); exit_sys(&c);
	expect_x("X5 lea rsp,[rbp-8]", &c, SWEEP, 1, 0, 0, KGENOME_OK);

	/* a cdecl call in a loop of straight-line copies: 40 `push 5; call f; add rsp,8` grew the depth by 40 and
	 * the ring holds 32, so the socket pushed first was overwritten (TRUNCATED) and the pop found nothing */
	for (i = 0; i < 2u; i++) {
		unsigned n = i ? 40u : 31u, k, h[64], f;

		c.n = 0; sock(&c); mov_rdi_rax(&c); E(&c, 0x57);
		for (k = 0; k < n; k++) {
			E(&c, 0x6a, 0x05);
			h[k] = c.n; E(&c, 0xe8, 0, 0, 0, 0);
			E(&c, 0x48, 0x83, 0xc4, 0x08);
		}
		E(&c, 0x5f);
		write_sys(&c); exit_sys(&c);
		f = c.n; ret(&c);
		for (k = 0; k < n; k++)
			p32(c.b, h[k] + 1u, (uint32_t)(f - (h[k] + 5u)));
		expect_x(i ? "X5 40 cdecl calls" : "X5 31 cdecl calls", &c, SWEEP, 1, 0, 0, KGENOME_OK);
	}

	/* `call next; pop rbx` pushes a slot and takes it back: the socket pushed before it is still the top below (rbx, and
	 * not an argument register: the write must not find the socket through the pop by another road) */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	E(&c, 0x57, 0xe8, 0, 0, 0, 0, 0x5b, 0x5f);              /* push rdi; call next; pop rbx; pop rdi */
	write_sys(&c); exit_sys(&c);
	expect_x("X5 call next / pop", &c, SWEEP, 1, 0, 0, KGENOME_OK);
	/* the same through a callee that begins by popping its return address: call L; nop; nop; L: pop rbx */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	E(&c, 0x57, 0xe8, 2, 0, 0, 0, 0x90, 0x90, 0x5b, 0x5f);
	write_sys(&c); exit_sys(&c);
	expect_x("X5 call L / pop", &c, SWEEP, 1, 0, 0, KGENOME_OK);
	/* and when no caller-saved register carries anything at the call (the socket is in rbx, pushed): the callee is not
	 * read, only asked whether it fetches the program counter */
	c.n = 0; sock(&c);
	E(&c, 0x48, 0x89, 0xc3, 0x31, 0xc0, 0x53);                      /* mov rbx,rax; xor eax,eax; push rbx */
	E(&c, 0xe8, 2, 0, 0, 0, 0x90, 0x90, 0x59, 0x5b);                /* call L; nop; nop; L: pop rcx; pop rbx */
	E(&c, 0x48, 0x89, 0xdf);                                        /* mov rdi,rbx */
	write_sys(&c); exit_sys(&c);
	expect_x("X5 call L / pop, nothing carried across the call", &c, SWEEP, 1, 0, 0, KGENOME_OK);
	/* a callee that returns is balanced: nothing is pushed for it (call f; ... f: ret), the socket is still there */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	{
		unsigned h2;

		E(&c, 0x57);
		h2 = c.n; E(&c, 0xe8, 0, 0, 0, 0);
		E(&c, 0x5f);
		write_sys(&c); exit_sys(&c);
		p32(c.b, h2 + 1u, (uint32_t)(c.n - (h2 + 5u)));
		ret(&c);
	}
	expect_x("X5 control, call f / ret is balanced", &c, SWEEP, 1, 0, 0, KGENOME_OK);

	/* a frame bigger than the ring (0x1000 bytes is 512 slots): recording it would push the socket below it out of the
	 * window (and lose what the program still has, with a status that makes the file "broken"), so the room is counted
	 * instead and given back by the `add`: the socket is still the one the pop takes */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	E(&c, 0x57, 0x48, 0x81, 0xec, 0x00, 0x10, 0, 0, 0x48, 0x81, 0xc4, 0x00, 0x10, 0, 0, 0x5f);
	write_sys(&c); exit_sys(&c);
	expect_x("X5 frame bigger than the ring", &c, SWEEP, 1, 0, 0, KGENOME_OK);
}

/* ---- X3: back edges ---------------------------------------------------------------------------- */

static void jnz_back(struct cb *c, unsigned target)
{
	E(c, 0x0f, 0x85, 0, 0, 0, 0);
	p32(c->b, c->n - 4u, (uint32_t)(target - c->n));
}
static void jmp_back(struct cb *c, unsigned target)
{
	E(c, 0xe9, 0, 0, 0, 0);
	p32(c->b, c->n - 4u, (uint32_t)(target - c->n));
}

static void t_x3_loops(void)
{
	static struct cb c;
	unsigned loop, i;

	/* the body writes rdi from a second socket: on the second pass the write takes THAT one */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); sock(&c); mov_rdi_rax(&c); test_rcx(&c); jnz_back(&c, loop);
	exit_sys(&c);
	expect_x("X3 loop rewrites rdi", &c, SWEEP, 0, 1, 2, KGENOME_OK);

	/* the body kills it: first pass the socket, later none, so MAY */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); E(&c, 0x31, 0xff); test_rcx(&c); jnz_back(&c, loop);
	exit_sys(&c);
	expect_x("X3 loop kills rdi", &c, SWEEP, 0, 1, 1, KGENOME_OK);

	/* an unconditional back edge */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); sock(&c); mov_rdi_rax(&c); jmp_back(&c, loop);
	expect_x("X3 jmp back, loop rewrites rdi", &c, SWEEP, 0, 1, 2, KGENOME_OK);

	/* control: the body only reads rdi, so the link stays PROVEN (a fix that demotes every link in a loop fails here) */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); E(&c, 0x48, 0xff, 0xc9); jnz_back(&c, loop);
	exit_sys(&c);
	expect_x("X3 control, loop only reads rdi", &c, SWEEP, 1, 0, 0, KGENOME_OK);

	/* control: a loop that sets rdi again BEFORE it reads it: every pass the write takes the body's socket */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	loop = c.n; sock(&c); mov_rdi_rax(&c); write_sys(&c); test_rcx(&c); jnz_back(&c, loop);
	exit_sys(&c);
	expect_x("X3 control, loop sets rdi before the read", &c, SWEEP, 1, 0, 0, KGENOME_OK);

	/* control: a loop that carries nothing is read once - no origin, no second pass (3 instructions and the exit's 2) */
	c.n = 0;
	loop = c.n; E(&c, 0x48, 0xff, 0xc9); jnz_back(&c, loop); exit_sys(&c);
	cell_next_calls = 0;
	{
		struct kgenome_diag_scan *s0 = scan_cb(&c, SWEEP);

		CK(s0 != NULL);
		if (s0)
			kgenome_diag_scan_free(s0);
		if (cell_next_calls != 4u) {
			printf("  FAIL X3 control, a loop that carries nothing: %u instructions decoded, wanted 4\n", cell_next_calls);
			hk_fails++;
		}
	}

	/* the cap on the loops of one window (32): at the cap every link stays PROVEN, one past it is MAY and said */
	for (i = 0; i < 2u; i++) {
		const unsigned n = i ? 33u : 32u;
		unsigned k;
		struct kgenome_diag_scan *s;
		unsigned m, y;

		c.n = 0; sock(&c); mov_rdi_rax(&c);
		for (k = 0; k < n; k++) {
			loop = c.n; write_sys(&c); E(&c, 0x48, 0xff, 0xc9); jnz_back(&c, loop);
		}
		exit_sys(&c);
		cell_next_calls = 0;
		s = scan_cb(&c, SWEEP);
		CK(s != NULL);
		if (!s)
			continue;
		/* the work: two passes over the window at most (8 + 4 per loop instructions in it), whatever the loop count */
		if (cell_next_calls > 2u * (8u + 4u * n) || cell_next_calls < 8u + 4u * n) {
			printf("  FAIL X3 %u loops: %u instructions decoded, wanted %u..%u\n", n, cell_next_calls, 8u + 4u * n,
			       2u * (8u + 4u * n));
			hk_fails++;
		}
		write_links(s, &m, &y);
		if (!i && (m != n || y != 0u || kgenome_diag_scan_status(s) != KGENOME_OK)) {
			printf("  FAIL X3 %u loops: PROVEN %u MAY %u status %s, wanted all PROVEN and ok\n", n, m, y,
			       kgenome_status_name(kgenome_diag_scan_status(s)));
			hk_fails++;
		}
		if (i && (m + y != n || y == 0u || kgenome_diag_scan_status(s) != KGENOME_TRUNCATED)) {
			printf("  FAIL X3 %u loops: PROVEN %u MAY %u status %s, wanted MAY for the loops past the cap and TRUNCATED\n",
			       n, m, y, kgenome_status_name(kgenome_diag_scan_status(s)));
			hk_fails++;
		}
		kgenome_diag_scan_free(s);
	}
}

/* the window machinery of the second pass: a RESUMED window, a head before the window began, and no table at all */
static void t_x3_windows(void)
{
	static struct cb c;
	unsigned loop, far_, m, y;
	struct kgenome_diag_scan *s;
	struct kgenome_budget bud;
	static struct kgenome_obj o;
	uint64_t al;

	/* A window put down at the idle bound and picked up by the next candidate: the second pass restores the joins the
	 * window found pending (a jz forward past the whole loop) and still takes back the first pass's claim */
	c.n = 0;
	write_sys(&c); test_rcx(&c); far_ = jz_fwd(&c); pad(&c, 70);
	sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); sock(&c); mov_rdi_rax(&c); test_rcx(&c); jnz_back(&c, loop);
	here(&c, far_); exit_sys(&c);
	expect_x("X3 loop in a resumed window", &c, SWEEP, 0, 1, 2, KGENOME_OK);
	/* its control: the same loop that only reads rdi keeps PROVEN through the pending join and the restore */
	c.n = 0;
	write_sys(&c); test_rcx(&c); far_ = jz_fwd(&c); pad(&c, 70);
	sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); E(&c, 0x48, 0xff, 0xc9); jnz_back(&c, loop);
	here(&c, far_); exit_sys(&c);
	expect_x("X3 control, loop in a resumed window only reads rdi", &c, SWEEP, 1, 0, 0, KGENOME_OK);

	/* a join that is pending when the window is put down - a jz past the loop, taken by a path holding socket one - is
	 * still pending when the second pass of the next window has run: the write after the loop gets both producers */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	test_rcx(&c); far_ = jz_fwd(&c);
	E(&c, 0x31, 0xff, 0x31, 0xc0);                                  /* xor edi,edi; xor eax,eax: nothing is carried now */
	pad(&c, 70);
	sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); E(&c, 0x48, 0xff, 0xc9); jnz_back(&c, loop);
	here(&c, far_); write_sys(&c); exit_sys(&c);
	expect_x("X3 resumed window keeps its pending join", &c, SWEEP, 1, 2, 2, KGENOME_OK);

	/* a head the window did not read (its reads were another window's): the claim is taken back without a second
	 * pass, and said */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); E(&c, 0x31, 0xff); pad(&c, 100);
	sock(&c); mov_rdi_rax(&c); test_rcx(&c); jnz_back(&c, loop);
	exit_sys(&c);
	expect_x("X3 head before the window", &c, SWEEP, 0, 1, 2, KGENOME_TRUNCATED);

	/* the allowance leaves no room for the tables of the sweep: no second pass is possible and the claim is taken
	 * back all the same - at no allowance does the first pass's PROVEN link come back */
	c.n = 0; sock(&c); mov_rdi_rax(&c);
	loop = c.n; write_sys(&c); E(&c, 0x31, 0xff); test_rcx(&c); jnz_back(&c, loop);
	exit_sys(&c);
	for (al = 4096; al <= (1u << 21); al += al / 5u + 1u) {
		memset(&bud, 0, sizeof bud);
		bud.max_bytes = al;
		s = scan_img(elf64(img, &c, 0), SWEEP, &bud, 0, &o);
		if (!s) {
			CK(0);
			continue;
		}
		write_links(s, &m, &y);
		if (m != 0u) {
			printf("  FAIL X3 allowance %llu: PROVEN %u, a loop that kills rdi\n", (unsigned long long)al, m);
			hk_fails++;
		}
		kgenome_diag_scan_free(s);
	}
}

/* the ring at the instruction level: the odd forms of what moves the stack pointer */
static void ring_step(struct kgenome_diag_orgs *w, unsigned arch, const uint8_t *b, unsigned n)
{
	struct kgenome_cell_insn in;

	CK(kgenome_cell_decode(arch, 0, b, n, 0x1000, &in) == n);
	kgenome_diag_org_step(w, &in);
}

static void ring_fresh(struct kgenome_diag_orgs *w, unsigned depth)
{
	unsigned r;

	memset(w, 0, sizeof *w);
	for (r = 0; r < 16u; r++)
		w->reg[r].node = KGENOME_DIAG_ORG_NONE;
	for (r = 0; r < depth; r++) {
		static const uint8_t push_rdi[] = { 0x57 };

		kgenome_diag_org_set(w, KGENOME_CELL_REG_DI, (uint16_t)(10u + r));
		ring_step(w, KGENOME_ARCH_X86_64, push_rdi, 1);
	}
}

/* AArch64's stack pointer is not x4: `mov x0,x4; write` made x0 "a stack address" (the walk read register 4 as the stack
 * pointer, as it does on x86), and the write took a link from the stack. */
static void t_arm64_stack(void)
{
	static struct cb c;
	struct kgenome_diag_scan *s;
	uint32_t i, cnt;
	unsigned stack_links = 0, k;

	elf_machine = 0xb7;
	c.n = 0;
	w32(&c, 0xaa0403e0u);                           /* mov x0, x4 */
	w32(&c, 0xd2800808u); w32(&c, 0xd4000001u);     /* write */
	w32(&c, 0xd2800ba8u); w32(&c, 0xd4000001u);     /* exit */
	s = scan_cb(&c, SWEEP);
	elf_machine = 0x3e;
	CK(s != NULL);
	if (!s)
		return;
	cnt = kgenome_diag_scan_count(s);
	CK(cnt >= 1u);
	for (i = 0; i < cnt; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		for (k = 0; k < h->n_in; k++)
			stack_links += h->in[k].from == KGENOME_DIAG_ORG_STACK;
	}
	if (stack_links) {
		printf("  FAIL X5 arm64: x4 read as the stack pointer (%u link(s) from the stack)\n", stack_links);
		hk_fails++;
	}
	kgenome_diag_scan_free(s);
}

static void t_x5_ring(void)
{
	struct kgenome_diag_orgs w;
	static const uint8_t add8[] = { 0x48, 0x83, 0xc4, 0x08 }, add4_64[] = { 0x48, 0x83, 0xc4, 0x04 },
		add_big[] = { 0x48, 0x81, 0xc4, 0x00, 0x01, 0, 0 }, add_huge[] = { 0x48, 0x81, 0xc4, 0x00, 0x10, 0, 0 }, sub_big[] = { 0x48, 0x81, 0xec, 0x00, 0x10, 0, 0 },
		sub_mid[] = { 0x48, 0x81, 0xec, 0xc0, 0, 0, 0 }, add_neg[] = { 0x48, 0x83, 0xc4, 0xf0 }, sub_neg[] = { 0x48, 0x83, 0xec, 0xf0 },
		add4_32[] = { 0x83, 0xc4, 0x04 }, sub8_32[] = { 0x83, 0xec, 0x08 },
		mov_bp_sp[] = { 0x48, 0x89, 0xe5 }, mov_sp_bp[] = { 0x48, 0x89, 0xec }, leave[] = { 0xc9 },
		lea_up[] = { 0x48, 0x8d, 0x65, 0x08 }, lea_down[] = { 0x48, 0x8d, 0x65, 0xe8 }, pop_bp[] = { 0x5d },
		mov_bp_ax[] = { 0x48, 0x89, 0xc5 }, push_rsi[] = { 0x56 }, add_reg[] = { 0x48, 0x01, 0xc4 };

	/* add rsp,8 gives up one slot; the slot below keeps its producer */
	ring_fresh(&w, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, add8, 4);
	CK(w.n_stk == 2u && w.stk[1] == 11u);
	/* a word that is not a whole number of slots: nothing moves (the unit is the register's width) */
	ring_fresh(&w, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, add4_64, 4);
	CK(w.n_stk == 3u);
	/* a 32-bit stack pointer has 4-byte slots */
	ring_fresh(&w, 3);
	ring_step(&w, KGENOME_ARCH_X86, add4_32, 3);
	CK(w.n_stk == 2u);
	ring_step(&w, KGENOME_ARCH_X86, sub8_32, 3);
	CK(w.n_stk == 4u && w.stk[2] == KGENOME_DIAG_ORG_NONE && w.stk[3] == KGENOME_DIAG_ORG_NONE);
	/* more than the ring holds: the ring is empty, the depth is not lost, and nothing below zero */
	ring_fresh(&w, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, add_big, 7);
	CK(w.n_stk == 0u && w.n_lost == 0u);
	ring_fresh(&w, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, sub_big, 7);
	CK(w.n_stk == 3u && w.sp_gap == 512u && !w.stk_cut);           /* counted, not pushed: nothing falls out of the ring */
	ring_step(&w, KGENOME_ARCH_X86_64, add_big, 7);                 /* 32 slots back: out of the room first */
	CK(w.n_stk == 3u && w.sp_gap == 480u);
	ring_step(&w, KGENOME_ARCH_X86_64, add_huge, 7);                /* 512 more than are left: the room is gone, no more */
	CK(w.n_stk == 0u && w.sp_gap == 0u);
	/* room that does fit is slots: 24 of 32, with 3 held */
	ring_fresh(&w, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, sub_mid, 7);
	CK(w.n_stk == 3u + 24u && w.sp_gap == 0u && w.stk[3] == KGENOME_DIAG_ORG_NONE);
	/* the same room when the ring has none left: counted, and no origin is lost */
	ring_step(&w, KGENOME_ARCH_X86_64, sub_mid, 7);
	CK(w.n_stk == 27u && w.sp_gap == 24u && !w.stk_cut && w.stk[0] == 10u);
	/* leave: the frame's room is given back with the rest */
	ring_fresh(&w, 2);
	ring_step(&w, KGENOME_ARCH_X86_64, mov_bp_sp, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, sub_big, 7);
	ring_step(&w, KGENOME_ARCH_X86_64, leave, 1);
	CK(w.n_stk == 1u && w.sp_gap == 0u && !w.bp_known);
	/* a negative immediate is the other direction */
	ring_fresh(&w, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, add_neg, 4);
	CK(w.n_stk == 5u);
	ring_step(&w, KGENOME_ARCH_X86_64, sub_neg, 4);
	CK(w.n_stk == 3u);
	/* an add by a register is not followed */
	ring_fresh(&w, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, add_reg, 3);
	CK(w.n_stk == 3u);
	/* the frame pointer: made, used by mov rsp,rbp and lea, unmade by anything that writes it */
	ring_fresh(&w, 2);
	ring_step(&w, KGENOME_ARCH_X86_64, mov_bp_sp, 3);
	CK(w.bp_known && w.bp_depth == 2u);
	ring_step(&w, KGENOME_ARCH_X86_64, push_rsi, 1);
	ring_step(&w, KGENOME_ARCH_X86_64, push_rsi, 1);
	CK(w.n_stk == 4u);
	ring_step(&w, KGENOME_ARCH_X86_64, mov_sp_bp, 3);
	CK(w.n_stk == 2u);
	ring_step(&w, KGENOME_ARCH_X86_64, lea_down, 4);                /* lea rsp,[rbp-0x18]: three slots below */
	CK(w.n_stk == 5u);
	ring_step(&w, KGENOME_ARCH_X86_64, lea_up, 4);                  /* lea rsp,[rbp+8]: one above the frame */
	CK(w.n_stk == 1u);
	ring_step(&w, KGENOME_ARCH_X86_64, mov_bp_ax, 3);
	CK(!w.bp_known);
	ring_step(&w, KGENOME_ARCH_X86_64, mov_sp_bp, 3);               /* no frame: not followed */
	CK(w.n_stk == 1u);
	ring_step(&w, KGENOME_ARCH_X86_64, lea_down, 4);
	CK(w.n_stk == 1u);
	/* leave with a frame: back to the frame pointer's depth and one more pop; without one it is not followed */
	ring_fresh(&w, 2);
	ring_step(&w, KGENOME_ARCH_X86_64, push_rsi, 1);
	ring_step(&w, KGENOME_ARCH_X86_64, mov_bp_sp, 3);
	ring_step(&w, KGENOME_ARCH_X86_64, push_rsi, 1);
	ring_step(&w, KGENOME_ARCH_X86_64, leave, 1);
	CK(w.n_stk == 2u && !w.bp_known && w.stk[1] == 11u && w.stk[0] == 10u);
	ring_fresh(&w, 2);
	ring_step(&w, KGENOME_ARCH_X86_64, leave, 1);
	CK(w.n_stk == 2u && !w.bp_known);
	/* pop rbp hands back the caller's frame pointer */
	ring_fresh(&w, 2);
	ring_step(&w, KGENOME_ARCH_X86_64, mov_bp_sp, 3);
	CK(w.bp_known);
	ring_step(&w, KGENOME_ARCH_X86_64, pop_bp, 1);
	CK(!w.bp_known);
	/* kill_stack gives the next function a frame of its own */
	ring_fresh(&w, 2);
	ring_step(&w, KGENOME_ARCH_X86_64, mov_bp_sp, 3);
	(void)kgenome_diag_org_kill_stack(&w);
	CK(!w.bp_known && w.n_stk == 0u);
	/* ARM and AArch64 are not x86: their stack pointer is not register 4, so register 4 is an ordinary one */
	{
		static const uint8_t a64_add[] = { 0x84, 0x20, 0x00, 0x91 };        /* add x4,x4,#8 */
		static const uint8_t a64_mov[] = { 0xe0, 0x03, 0x04, 0xaa };        /* mov x0,x4 */
		static const uint8_t a32_sub[] = { 0x10, 0xd0, 0x4d, 0xe2 };        /* sub sp,sp,#16 */

		ring_fresh(&w, 3);
		w.sp = 31u;
		ring_step(&w, KGENOME_ARCH_ARM64, a64_add, 4);
		CK(w.n_stk == 3u);
		ring_step(&w, KGENOME_ARCH_ARM64, a64_mov, 4);
		CK(kgenome_diag_org_of(&w, 0) != KGENOME_DIAG_ORG_STACK);
		ring_fresh(&w, 3);
		w.sp = 13u;
		ring_step(&w, KGENOME_ARCH_ARM, a32_sub, 4);
		CK(w.n_stk == 3u);
	}
}

/* An ELF64 with symbols: a section table, .text, a symbol table of sized STT_FUNC entries (the function table
 * the sweep reads). The code is at +0x78 as elf64() places it. */
static uint64_t elf64_funcs(uint8_t *b, const struct cb *c, const unsigned *off, const unsigned *len, unsigned nfn)
{
	static const char shs[] = "\0.text\0.symtab\0.strtab\0.shstrtab\0";
	const unsigned code = 0x78u, sym_off = al8(code + c->n), str_off = sym_off + (nfn + 1u) * 24u;
	const unsigned shstr_off = str_off + 1u + nfn * 4u, sh_off = al8(shstr_off + (unsigned)sizeof shs);
	unsigned i;
	uint8_t *p;

	elf64(b, c, 0);
	memset(b + code + c->n, 0, sh_off + 5u * 64u - (code + c->n));
	p64(b, 40, sh_off);
	p16(b, 60, 5); p16(b, 62, 4);                   /* shnum, shstrndx; shentsize is already 64 */
	p16(b, 58, 64);
	for (i = 0; i < nfn; i++) {
		p = b + sym_off + (i + 1u) * 24u;
		p32(p, 0, 1u + i * 4u);
		memcpy(b + str_off + 1u + i * 4u, "fn", 3);
		b[str_off + 1u + i * 4u + 2u] = (uint8_t)('0' + i);
		p[4] = 0x12;
		p16(p, 6, 1);
		p64(p, 8, 0x400000u + code + off[i]);
		p64(p, 16, len[i]);
	}
	memcpy(b + shstr_off, shs, sizeof shs);
	p = b + sh_off;
	p32(p + 64, 0, 1); p32(p + 64, 4, 1); p64(p + 64, 8, 6);                        /* .text */
	p64(p + 64, 16, 0x400000u + code); p64(p + 64, 24, code); p64(p + 64, 32, c->n); p64(p + 64, 48, 16);
	p32(p + 128, 0, 7); p32(p + 128, 4, 2); p64(p + 128, 24, sym_off);              /* .symtab */
	p64(p + 128, 32, (nfn + 1u) * 24u); p32(p + 128, 40, 3);
	p32(p + 128, 44, 1); p64(p + 128, 48, 8); p64(p + 128, 56, 24);
	p32(p + 192, 0, 15); p32(p + 192, 4, 3); p64(p + 192, 24, str_off);             /* .strtab */
	p64(p + 192, 32, 1u + nfn * 4u); p64(p + 192, 48, 1);
	p32(p + 256, 0, 23); p32(p + 256, 4, 3); p64(p + 256, 24, shstr_off);           /* .shstrtab */
	p64(p + 256, 32, sizeof shs); p64(p + 256, 48, 1);
	return sh_off + 5u * 64u;
}

static void expect_funcs(const char *what, const struct cb *c, const unsigned *off, const unsigned *len, unsigned nfn,
			 unsigned must, unsigned may)
{
	static struct kgenome_obj o;
	struct kgenome_diag_scan *s = scan_img(elf64_funcs(img, c, off, len, nfn), SWEEP, NULL, 0, &o);
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

static void t_x3_tail(void)
{
	static struct cb c;
	unsigned off[4], len[4], h, a;

	/* A makes the socket and tail-jumps to B; C, which is the next function, writes. The code after the jmp
	 * is C: nothing reaches it, so its rdi holds nothing of A's. */
	c.n = 0; off[0] = 0;
	sock(&c); mov_rdi_rax(&c); h = jmp_fwd(&c);
	len[0] = c.n;
	off[1] = c.n; write_sys(&c); ret(&c); len[1] = c.n - off[1];             /* C */
	off[2] = c.n; here(&c, h); E(&c, 0x31, 0xc0); ret(&c); len[2] = c.n - off[2];   /* B */
	expect_funcs("X3 tail jmp into another function", &c, off, len, 3, 0, 0);

	/* control: the same bytes with the jump inside ONE function: a jmp/call/pop idiom, the code after it is reached
	 * by a call later on and keeps the origin as MAY */
	c.n = 0; off[0] = 0;
	sock(&c); mov_rdi_rax(&c); h = jmp_fwd(&c);
	a = c.n; write_sys(&c); ret(&c);                                        /* back: */
	here(&c, h);
	call_to(&c, a); exit_sys(&c);
	len[0] = c.n;
	expect_funcs("X3 control, jmp over code a later call reaches", &c, off, len, 1, 0, 1);

	/* control: a symbol table with no function in it (the functions are the entries the code is seen to call) is not a
	 * function table either: the idiom's own `call back` makes `back` an entry, and the jmp over it is not a tail jump */
	c.n = 0; off[0] = 0;
	sock(&c); mov_rdi_rax(&c); h = jmp_fwd(&c);
	a = c.n; write_sys(&c); ret(&c);
	here(&c, h);
	call_to(&c, a); exit_sys(&c);
	expect_funcs("X3 control, symbols but no function symbols", &c, off, len, 0, 0, 1);

	/* control: no function table at all (stripped) leaves the idiom's rule, and does not build the table to find out
	 * (the table of a stripped file is a walk over the whole file) */
	c.n = 0;
	sock(&c); mov_rdi_rax(&c); h = jmp_fwd(&c);
	write_sys(&c); ret(&c);
	here(&c, h);
	E(&c, 0x31, 0xc0); ret(&c);
	funcs_calls = 0;
	expect("X3 control, stripped: code after a jmp", &c, SWEEP, 0, 1);
	if (funcs_calls != 0u) {
		printf("  FAIL X3 stripped: the function table was asked for %u time(s)\n", funcs_calls);
		hk_fails++;
	}
}

/* ---- X8: a relocatable object whose image cannot be built ---------------------------------------- */

static void t_x8(void)
{
	static struct kmod m;
	static struct kgenome_obj o;
	struct kgenome_budget bud;
	struct kgenome_diag_scan *s;
	enum kgenome_status st;
	uint64_t len;
	unsigned ok = 0, refused = 0, nomem = 0, other = 0, seen_ok = 0;
	uint64_t a;

	/* the kmod_give_root shape: two nodes in one function and a producer, so the emulate route builds the image */
	km_start(&m);
	km_call(&m, "prepare_creds"); E(&m.c, 0x48, 0x89, 0xc7);
	E(&m.c, 0x48, 0xc7, 0x47, 0x08, 0, 0, 0, 0);                    /* mov qword [rdi+8],0 */
	km_call(&m, "commit_creds"); ret(&m.c);
	len = km_image(&m);

	/* with the default allowance the image is built and the run happens */
	s = scan_img(len, KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_EMULATE, NULL, 0, &o);
	CK(s != NULL);
	if (s) {
		want_status("X8 default allowance", s, KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
	/* a growing allowance: below what the image needs the build fails and the BUDGET says so, never "out of
	 * memory" and never a clean status; above it the run is whole. Monotone: once it is ok it stays ok. */
	for (a = 4096; a <= (64u << 20); a += a / 3u + 1u) {
		memset(&bud, 0, sizeof bud);
		bud.max_bytes = a;
		km_image(&m);
		s = scan_img(len, KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_EMULATE, &bud, 0, &o);
		if (!s) {
			CK(0);
			continue;
		}
		st = kgenome_diag_scan_status(s);
		if (st == KGENOME_OK) {
			ok++;
			seen_ok = 1;
		} else if (st == KGENOME_OVER_BUDGET) {
			refused++;
			if (seen_ok) {
				printf("  FAIL X8 allowance %llu: over budget after an allowance that was ok\n", (unsigned long long)a);
				hk_fails++;
			}
		} else if (st == KGENOME_NOMEM) {
			nomem++;
		} else {
			other++;
		}
		kgenome_diag_scan_free(s);
	}
	printf("  X8: %u ok, %u over-budget, %u nomem, %u other\n", ok, refused, nomem, other);
	CK(refused > 0 && ok > 0);
	CK(nomem == 0);
	CK(other == 0);
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
	t_x1();
	t_x2();
	t_x5();
	t_x3_loops();
	t_x3_tail();
	t_x3_windows();
	t_x5_ring();
	t_arm64_stack();
	t_x8();
	printf("diag_graph_bin: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
