/*
 * emu_oep_stale - the emulator's handover test (kofemu.c run_landed) reads the
 * SHAPE of the transfer from the fetch buffer, which an instruction-cache hit
 * does not fill.
 *
 * THE SAME CAUSE as emu_syscall_watch.c's KNOWN-MISS, at its second reader: in
 * kgenome_emu_run `at_b` is the 16-byte fetch buffer, a cache MISS fills it, and
 * a HIT leaves it holding whatever was last decoded. The watch for `syscall`
 * (iwatch_hit) compares it; so does the handover test, which asks whether the
 * instruction that just transferred control was one of the four tails a packer
 * ends with (jmp/call rel32, ret, ret imm16, jmp/call reg). A transfer made by a
 * CACHED instruction is judged by the bytes of the last one decoded, and a stub
 * that reaches its tail through a dispatcher it has run before is not recognised.
 *
 * THE FIXTURE is a dispatcher that is run twice:
 *
 *       mov rax,B        ; the first destination: outside the image
 *       mov rdx,T ; mov byte [rdx],0xc3    the guest WRITES the target's page
 *   D:  jmp rax          <- run twice: a decode the first time, a cache hit after
 *   B:  mov rax,T ; jmp D
 *   T:  ret              <- in the image, a written page, stack as the stub found it
 *
 * the second `jmp rax` is the handover: the target is on a page the guest wrote,
 * inside the image, the stack is balanced, the tail is `ff e0`. The control runs
 * the same transfer as a first visit (a decode) and is recognised.
 *
 * The expectation is written as the correct behaviour and is a KM_CHECK today;
 * FIXED-UNEXPECTEDLY is the signal to make it a plain check and to re-read the
 * notes in diag_emu_int.h and emu_syscall_watch.c.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/kofemu.h>

#include "known_miss.h"

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
	c[at++] = 0xeb;                                         /* jmp D           */
	c[at] = (uint8_t)(d - (at + 1u)); at++;
	return at;
}

/* Run the fixture; returns the stop and leaves the detail in `detail`. */
static enum kgenome_emu_stop run(int twice, char *detail, unsigned cap)
{
	uint8_t c[512];
	struct kgenome_emu_cfg cfg = { 0 };
	struct kgenome_emu *e;
	enum kgenome_emu_stop st;
	unsigned n;

	memset(c, 0, sizeof c);
	n = build(c, twice);
	cfg.bits = 64;
	cfg.max_insn = 10000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return KGENOME_EMU_STOP_FAULT;
	kgenome_emu_map(e, CODE_VA, c, n, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, IMG_LO, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	kgenome_emu_map(e, STACK_VA, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, CODE_VA);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK_VA + 0x800);
	kgenome_emu_set_image_range(e, IMG_LO, IMG_HI);
	kgenome_emu_set_oep_watch(e, 1);
	st = kgenome_emu_run(e);
	snprintf(detail, cap, "%s", kgenome_emu_stop_detail(e));
	kgenome_emu_free(e);
	return st;
}

int main(void)
{
	char d[128];
	enum kgenome_emu_stop st;

	/* the control: the same transfer as a first visit is recognised */
	st = run(0, d, sizeof d);
	CK(st == KGENOME_EMU_STOP_HANDOFF);
	CK(strstr(d, "handover") != NULL);

	/* the second visit to the same `jmp rax` is the same handover */
	st = run(1, d, sizeof d);
	printf("    measured: stop %d, '%s'\n", (int)st, d);
	KM_CHECK(st == KGENOME_EMU_STOP_HANDOFF && strstr(d, "handover") != NULL,
		 "a handover made by a cached `jmp rax` is recognised",
		 "EMU_AT_B_STALE_OEP");

	printf("emu oep stale: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
