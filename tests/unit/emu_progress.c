/*
 * emu_progress - what counts as a guest still working, for the stall test.
 *
 * A run is stopped as STALLED when it has gone a stated number of instructions
 * without producing anything. "Producing" began as "wrote a page for the first
 * time", which is right for a decompressor and wrong for the pass that follows
 * one: the call-operand unfilter at the end of a UPX stub sweeps the whole
 * decompressed image patching a few bytes per call site, every byte on a page
 * already written. Measured on four UPX 5 x64 samples that was a stall at 18-25
 * million instructions, with the jump to the entry point still to come.
 *
 * So a store to a new cache line of an already-written page also counts, up to a
 * bound; and a loop that hammers ONE line - which is what a delay or a wait for
 * a flag does - earns nothing past its first store.
 *
 *   sweeps  16 pages written once, then 200 passes patching every 64th byte:
 *           ~820 000 instructions against an idle limit of 100 000. Must finish.
 *   spins   one line incremented for ever. Must be stopped as STALLED, near the
 *           idle limit and not at the budget.
 *
 * MUTATION CHECK, measured: with the line credit in mem_wr removed, `sweeps`
 * ends STALLED; with it made unconditional (no new-line test) `spins` runs to
 * the budget.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libgenome/phenotype/kofemu.h"

static int failures;

static void ck(int ok, const char *what)
{
	if (!ok) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

#define CODE_VA   0x400000ull
#define DATA_VA   0x800000ull
#define STACK_VA  0x7ffff000ull
#define IDLE      100000u
#define BUDGET    3000000u

static uint8_t sweeps[] = {
	0x48,0xBF, 0,0,0,0,0,0,0,0,              /* mov rdi, DATA          */
	0xB9, 0x10,0,0,0,                        /* mov ecx, 16            */
	0xC6,0x07,0x01,                          /* P1: mov byte [rdi], 1  */
	0x48,0x81,0xC7, 0x00,0x10,0,0,           /*     add rdi, 0x1000    */
	0xFF,0xC9,                               /*     dec ecx            */
	0x75,0xF2,                               /*     jnz P1             */
	0xBA, 0xC8,0,0,0,                        /* mov edx, 200           */
	0x48,0xBF, 0,0,0,0,0,0,0,0,              /* P2: mov rdi, DATA      */
	0xB9, 0x00,0x04,0,0,                     /*     mov ecx, 1024      */
	0x80,0x07,0x01,                          /* P3: add byte [rdi], 1  */
	0x48,0x83,0xC7,0x40,                     /*     add rdi, 64        */
	0xFF,0xC9,                               /*     dec ecx            */
	0x75,0xF5,                               /*     jnz P3             */
	0xFF,0xCA,                               /*     dec edx            */
	0x75,0xE2,                               /*     jnz P2             */
	0x31,0xFF,                               /* xor edi, edi           */
	0xB8, 0x3C,0,0,0,                        /* mov eax, 60            */
	0x0F,0x05                                /* syscall                */
};

static uint8_t spins[] = {
	0x48,0xBF, 0,0,0,0,0,0,0,0,              /* mov rdi, DATA          */
	0xFE,0x07,                               /* L: inc byte [rdi]      */
	0xEB,0xFC                                /*     jmp L              */
};

static enum kof_emu_stop run(uint8_t *code, size_t n, uint64_t *insn)
{
	struct kof_emu_cfg cfg = { BUDGET, 0, 0, 0 };
	struct kof_emu *e = kof_emu_new(&cfg);
	enum kof_emu_stop st = KOF_EMU_STOP_DECODE;

	if (!e) {
		ck(0, "out of memory");
		return st;
	}
	if (!kof_emu_map(e, CODE_VA, code, n, 0x1000, KOF_EMU_R | KOF_EMU_X) ||
	    !kof_emu_map(e, DATA_VA, NULL, 0, 16u * 0x1000u,
			 KOF_EMU_R | KOF_EMU_W) ||
	    !kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W))
		ck(0, "map");
	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);
	kof_emu_set_idle(e, IDLE);
	st = kof_emu_run(e);
	*insn = kof_emu_insn_count(e);
	kof_emu_free(e);
	return st;
}

int main(void)
{
	uint64_t insn = 0;
	enum kof_emu_stop st;

	memcpy(sweeps + 2, &(uint64_t){ DATA_VA }, 8);
	memcpy(sweeps + 36, &(uint64_t){ DATA_VA }, 8);
	memcpy(spins + 2, &(uint64_t){ DATA_VA }, 8);

	st = run(sweeps, sizeof sweeps, &insn);
	printf("  sweeps: %llu instructions, stop=%s\n", (unsigned long long)insn,
	       kof_emu_stop_name(st));
	ck(st == KOF_EMU_STOP_EXIT, "a sweep over written pages is work, not a stall");
	ck(insn > 5u * IDLE, "and it ran well past the idle limit to finish");

	st = run(spins, sizeof spins, &insn);
	printf("  spins: %llu instructions, stop=%s\n", (unsigned long long)insn,
	       kof_emu_stop_name(st));
	ck(st == KOF_EMU_STOP_STALLED, "a loop on one line is stopped as stalled");
	ck(insn < 4u * IDLE, "near the idle limit and not at the budget");

	printf("emu progress: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
