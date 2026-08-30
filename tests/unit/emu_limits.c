/*
 * emu_limits - what a guest can make the emulator spend, and where it stops.
 *
 * The interpreter cannot touch the host directly: it makes no system call and
 * the only file it can see is the buffer it was handed. What it CAN do is ask
 * for things, in a loop, and the answer has to be a ceiling rather than growth.
 * Three asks cost the host memory that the guest never has to pay for:
 *
 *   mmap        a reservation commits no page, so a loop of them grows a list
 *               in the host and nothing in the guest
 *   mprotect    granting PROT_EXEC over written pages COPIES them, so a loop
 *               of that copies the address space once per call
 *   touching    pages are the ordinary cost, and cfg.max_pages bounds them
 *
 * Each stub below does one of those as hard as it can, inside an instruction
 * budget it is not allowed to exceed either. What is asserted is that the run
 * ends, that it ends within the budget, and that the emulator's own structures
 * stopped growing at the stated ceiling rather than at the point malloc failed.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofemu/kofemu.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

#define CODE_VA   0x400000ull
#define SCRATCH   0x401000ull
#define STACK_VA  0x7ffff000ull
#define BUDGET    200000ull
#define PAGES     512u                 /* 2 MB of guest address space */

/*
 * mmap(NULL, 0x1000, PROT_NONE, MAP_PRIVATE|MAP_ANON, -1, 0) forever.
 * PROT_NONE so each one is a reservation: no page, only a record.
 */
static uint8_t mmap_loop[] = {
	0x48,0x31,0xFF,                          /* xor  rdi, rdi     */
	0x48,0xC7,0xC6, 0x00,0x10,0x00,0x00,     /* mov  rsi, 0x1000  */
	0x48,0x31,0xD2,                          /* xor  rdx, rdx     */
	0x49,0xC7,0xC2, 0x22,0x00,0x00,0x00,     /* mov  r10, 0x22    */
	0x49,0xC7,0xC0, 0xFF,0xFF,0xFF,0xFF,     /* mov  r8, -1       */
	0x4D,0x31,0xC9,                          /* xor  r9, r9       */
	0x48,0xC7,0xC0, 0x09,0x00,0x00,0x00,     /* mov  rax, 9       */
	0x0F,0x05,                               /* syscall           */
	0xEB,0xD7                                /* jmp  -41, to 0    */
};

/*
 * Write a byte into the scratch page, then mprotect it PROT_READ|PROT_EXEC,
 * forever: each call is a snapshot of memory the run has written.
 */
static uint8_t snap_loop[] = {
	0x48,0xBF, 0,0,0,0,0,0,0,0,              /*  0 movabs rdi, SCRATCH */
	0xC6,0x07,0x41,                          /* 10 mov byte [rdi], 'A' */
	0x48,0xC7,0xC6, 0x00,0x10,0x00,0x00,     /* 13 mov rsi, 0x1000     */
	0x48,0xC7,0xC2, 0x05,0x00,0x00,0x00,     /* 20 mov rdx, 5          */
	0x48,0xC7,0xC0, 0x0A,0x00,0x00,0x00,     /* 27 mov rax, 10         */
	0x0F,0x05,                               /* 34 syscall             */
	0xEB,0xDA                                /* 36 jmp -38             */
};

/*
 * Walk forward a page at a time writing one byte, forever: the ordinary way to
 * spend pages, and the one cfg.max_pages is for.
 */
static uint8_t page_loop[] = {
	0x48,0xBF, 0,0,0,0,0,0,0,0,              /*  0 movabs rdi, SCRATCH */
	0xC6,0x07,0x41,                          /* 10 mov byte [rdi], 'A' */
	0x48,0x81,0xC7, 0x00,0x10,0x00,0x00,     /* 13 add rdi, 0x1000     */
	0xEB,0xF6                                /* 20 jmp -10             */
};

static void run_one(const char *what, uint8_t *code, uint32_t n)
{
	struct kof_emu_cfg cfg = { BUDGET, PAGES, 0 };
	struct kof_emu *e = kof_emu_new(&cfg);
	enum kof_emu_stop st;
	uint32_t it = 0, snaps = 0;
	uint64_t va, len, held = 0;
	const uint8_t *bytes;

	if (!e) { fail("out of memory"); return; }
	if (!kof_emu_map(e, CODE_VA, code, n, 0x1000, KOF_EMU_R | KOF_EMU_X) ||
	    !kof_emu_map(e, SCRATCH, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W) ||
	    !kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W))
		fail("map");
	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);

	st = kof_emu_run(e);
	while (kof_emu_next_snapshot(e, &it, &va, &bytes, &len)) {
		snaps++;
		held += len;
	}
	printf("  %-18s %7llu lệnh  dừng=%-11s ảnh=%u (%llu KB)\n",
	       what, (unsigned long long)kof_emu_insn_count(e),
	       kof_emu_stop_name(st), snaps, (unsigned long long)(held >> 10));

	/*
	 * The budget is the CPU bound and nothing may exceed it - not a REP
	 * iteration, not a syscall that loops internally.
	 */
	if (kof_emu_insn_count(e) > BUDGET)
		fail("the run went past its instruction budget");
	if (st == KOF_EMU_STOP_UNSUPPORTED || st == KOF_EMU_STOP_DECODE)
		fail("the stub did not assemble to what this test meant");
	if (snaps > KOF_EMU_MAX_SNAP)
		fail("more snapshots were kept than the ceiling allows");
	/* Copies must not outgrow the address space the guest was given. */
	if (held > (uint64_t)PAGES * KOF_EMU_PAGE)
		fail("snapshots hold more than the guest's whole address space");
	kof_emu_free(e);
}

int main(void)
{
	memcpy(snap_loop + 2, &(uint64_t){ SCRATCH }, 8);
	memcpy(page_loop + 2, &(uint64_t){ SCRATCH }, 8);

	run_one("mmap không dứt",  mmap_loop, (uint32_t)sizeof mmap_loop);
	run_one("mprotect X lặp",  snap_loop, (uint32_t)sizeof snap_loop);
	run_one("chạm trang mãi",  page_loop, (uint32_t)sizeof page_loop);

	printf("emu limits: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
