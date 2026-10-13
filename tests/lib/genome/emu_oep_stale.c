/*
 * emu_oep_stale - the emulator's handover test (emu_interp.c run_landed) reads the SHAPE of the
 * transfer from the instruction that just ran, and that must be the instruction's own bytes
 * whether it came out of the instruction cache or was decoded fresh.
 *
 * THE DEFECT THIS GUARDS (it was a KNOWN-MISS here until fixed): in kgenome_emu_run the bytes
 * were a pointer at the 16-byte fetch buffer, which a cache MISS filled and a HIT left holding
 * whatever was last decoded. The watch for `syscall` (iwatch_hit) compared it, and so did the
 * handover test, which asks whether the instruction that just transferred control was one of the
 * four tails a packer ends with (jmp/call rel32, ret, ret imm16, jmp/call reg). The bytes, the
 * length and the address now come from ONE per-step record (run_step) filled the same way on a
 * hit and a miss.
 *
 * THE FIXTURES
 *
 * 1. a dispatcher that is run twice (`dispatch`):
 *
 *       mov rax,B        ; the first destination: outside the image
 *       mov rdx,T ; mov byte [rdx],0xc3    the guest WRITES the target's page
 *   D:  jmp rax          <- run twice: a decode the first time, a cache hit after
 *   B:  mov rax,T ; jmp D
 *   T:  ret              <- in the image, a written page, stack as the stub found it
 *
 *    the second `jmp rax` is the handover: the target is on a page the guest wrote, inside the
 *    image, the stack is balanced, the tail is `ff e0`. It must be recognised exactly as the
 *    first-visit control is. (The first version of this fixture reached D from B with a rel8
 *    that could not reach, so the dispatcher never ran twice - it ended in a fetch fault and the
 *    check was a miss for the wrong reason. B now jumps with a rel32.)
 *
 * 2. the converse (`false_tail`): a CACHED `jz rel8` (two bytes, not a tail) taken into a written
 *    page of the image, run right after a decoded `jmp rax` (`ff e0`). A stale buffer reads the
 *    jz as the tail and ends the run as a handover that is not one. It must not.
 *
 * Each fixture is also run with the instruction cache forced off and on, and the two must agree
 * on the stop, its text, the instruction count, rip and every register.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/emu.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define CODE_VA  0x400000ull
#define IMG_LO   0x500000ull
#define IMG_HI   0x510000ull
#define STACK_VA 0x7ff00000ull

static void imm64(uint8_t *c, unsigned at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		c[at + i] = (uint8_t)(v >> (8u * i));
}

/*
 * `twice` 0: the first `jmp rax` goes straight to T (a decode: the control).
 * `twice` 1: it goes to B first and the handover is the second visit (a hit).
 */
static unsigned build(uint8_t *c, int twice)
{
	unsigned at = 0, d;

	c[at++] = 0x48; c[at++] = 0xb8;                         /* mov rax,imm64   */
	imm64(c, at, twice ? CODE_VA + 0x100 : IMG_LO); at += 8;
	c[at++] = 0x48; c[at++] = 0xba;                         /* mov rdx,T       */
	imm64(c, at, IMG_LO); at += 8;
	c[at++] = 0xc6; c[at++] = 0x02; c[at++] = 0xc3;         /* mov byte [rdx],0xc3 */
	d = at;
	c[at++] = 0xff; c[at++] = 0xe0;                         /* D: jmp rax      */
	/* B at +0x100 */
	at = 0x100;
	c[at++] = 0x48; c[at++] = 0xb8;                         /* mov rax,T       */
	imm64(c, at, IMG_LO); at += 8;
	/* jmp D: rel32. A rel8 cannot reach back 0xf5 bytes - the first version of this
	 * fixture used one, the jump landed in zeros and the run ended in a fetch fault,
	 * so the "cached jmp rax" was never executed twice at all. */
	c[at++] = 0xe9;                                         /* jmp D           */
	{
		uint32_t rel = (uint32_t)((int32_t)d - (int32_t)(at + 4u));
		unsigned i;

		for (i = 0; i < 4u; i++)
			c[at + i] = (uint8_t)(rel >> (8u * i));
		at += 4;
	}
	return at;
}

struct outcome {
	enum kgenome_emu_stop st;
	char detail[128];
	uint64_t insn, rip, gpr[16];
};

/*
 * `kind` 0/1: the dispatcher (see build); 2: the false tail. `ic` is the instruction cache,
 * on or off.
 */
static unsigned build_false(uint8_t *c)
{
	unsigned at = 0, l, t_off = 0x80, i;

	c[at++] = 0x48; c[at++] = 0xba;                         /* mov rdx,T        */
	imm64(c, at, CODE_VA + t_off); at += 8;
	c[at++] = 0xc6; c[at++] = 0x02; c[at++] = 0x90;         /* mov byte [rdx],0x90: write the page */
	c[at++] = 0xb9; c[at++] = 1; c[at++] = 0; c[at++] = 0; c[at++] = 0; /* mov ecx,1 */
	c[at++] = 0x48; c[at++] = 0xb8;                         /* mov rax,L        */
	l = at + 8u;
	imm64(c, at, CODE_VA + l); at += 8;
	/* L: */
	c[at++] = 0x85; c[at++] = 0xc9;                         /* L: test ecx,ecx  */
	c[at++] = 0x74;                                         /* jz T (short)     */
	c[at] = (uint8_t)(t_off - (at + 1u)); at++;
	c[at++] = 0xff; c[at++] = 0xc9;                         /* dec ecx          */
	c[at++] = 0xff; c[at++] = 0xe0;                         /* jmp rax          */
	CK(at < t_off);
	for (i = at; i < t_off; i++)
		c[i] = 0x90;
	at = t_off;
	c[at++] = 0x90;                                         /* T: nop (written) */
	c[at++] = 0xb8; c[at++] = 231; c[at++] = 0; c[at++] = 0; c[at++] = 0; /* mov eax,231 */
	c[at++] = 0x31; c[at++] = 0xff;                         /* xor edi,edi      */
	c[at++] = 0x0f; c[at++] = 0x05;                         /* syscall: exit_group */
	return at;
}

static struct outcome run_kind(int kind, int ic)
{
	uint8_t c[512];
	struct kgenome_emu_cfg cfg = { 0 };
	struct kgenome_emu *e;
	struct outcome o;
	unsigned n, r;

	memset(&o, 0, sizeof o);
	memset(c, 0, sizeof c);
	n = kind == 2 ? build_false(c) : build(c, kind);
	cfg.bits = 64;
	cfg.max_insn = 10000;
	e = kgenome_emu_new(&cfg);
	if (!e) {
		o.st = KGENOME_EMU_STOP_FAULT;
		return o;
	}
	kgenome_emu_set_icache(e, ic);
	if (kind == 2) {
		/* the code page is the image, and writable: the guest writes into it */
		kgenome_emu_map(e, CODE_VA, c, n, 0x1000,
				KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
		kgenome_emu_set_image_range(e, CODE_VA, CODE_VA + 0x1000);
	} else {
		kgenome_emu_map(e, CODE_VA, c, n, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
		kgenome_emu_map(e, IMG_LO, NULL, 0, 0x1000,
				KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
		kgenome_emu_set_image_range(e, IMG_LO, IMG_HI);
	}
	kgenome_emu_map(e, STACK_VA, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, CODE_VA);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK_VA + 0x800);
	kgenome_emu_set_oep_watch(e, 1);
	o.st = kgenome_emu_run(e);
	snprintf(o.detail, sizeof o.detail, "%s", kgenome_emu_stop_detail(e));
	o.insn = kgenome_emu_insn_count(e);
	o.rip = kgenome_emu_get_rip(e);
	for (r = 0; r < 16u; r++)
		o.gpr[r] = kgenome_emu_get_reg(e, r);
	kgenome_emu_free(e);
	return o;
}

/* The same fixture with the cache off and on must be one run. */
static void cache_equal(int kind)
{
	struct outcome off = run_kind(kind, 0), on = run_kind(kind, 1);

	CK(off.st == on.st);
	CK(!strcmp(off.detail, on.detail));
	CK(off.insn == on.insn);
	CK(off.rip == on.rip);
	CK(!memcmp(off.gpr, on.gpr, sizeof off.gpr));
}

int main(void)
{
	struct outcome o;

	/* the control: the same transfer as a first visit is recognised */
	o = run_kind(0, 1);
	CK(o.st == KGENOME_EMU_STOP_HANDOFF);
	CK(strstr(o.detail, "handover") != NULL);

	/* the second visit to the same `jmp rax` (a cache hit) is the same handover */
	o = run_kind(1, 1);
	printf("    measured: stop %d, '%s'\n", (int)o.st, o.detail);
	CK(o.st == KGENOME_EMU_STOP_HANDOFF);
	CK(strstr(o.detail, "handover") != NULL);
	/* ...and the run took the second lap to get there, not the first */
	CK(o.insn > run_kind(0, 1).insn);

	/* a cached two-byte conditional jump after a decoded `ff e0` is not a tail */
	o = run_kind(2, 1);
	printf("    measured: stop %d, '%s'\n", (int)o.st, o.detail);
	CK(o.st == KGENOME_EMU_STOP_EXIT);
	CK(strstr(o.detail, "handover") == NULL);

	cache_equal(0);
	cache_equal(1);
	cache_equal(2);

	printf("emu oep stale: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
