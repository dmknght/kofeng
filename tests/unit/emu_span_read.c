/*
 * emu_span_read - reading what a run left, in spans, after it has stopped.
 *
 * WHY THIS IS PINNED. A module that recognises a family by searching what the
 * interpreter decrypted does not read a structure at a known address; it reads
 * the region in overlapping chunks and looks through them, and the chunks are
 * page-sized and unaligned by construction. `bases/unp/sality_pe.c` does
 * exactly this. Two guarantees hold that up and neither is obvious:
 *
 *   A SPAN MAY CROSS A PAGE BOUNDARY. Pages are the interpreter's unit and a
 *   4096-byte read at an unaligned address always touches two of them. If a
 *   read like that ever answered only the first page, a signature straddling
 *   the boundary would stop being found - and nothing would report an error,
 *   because a search that finds nothing looks exactly like a file that is
 *   clean.
 *
 *   AND IT MAY BE MADE AFTER THE RUN HAS STOPPED. The machine outlives the
 *   run; a module searches once the stub has finished, not while it runs.
 *
 *   AND A SPAN WITH ONE END UNMAPPED ANSWERS NOTHING, not the part that was
 *   there. kofemu.h calls a partial read "the failure mode this whole module
 *   is arranged to make impossible"; a search that accepted one would match
 *   against whatever the caller's buffer happened to hold.
 *
 * The marker below is written by the stub ACROSS the boundary on purpose - it
 * is not in the file, the run puts it there, which is the case that matters.
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

#define CODE_VA  0x400000ull
#define DATA_VA  0x401000ull       /* two pages: 0x401000 and 0x402000 */
#define DATA_LEN 0x2000u
#define MARK_VA  0x401ffcull       /* 8 bytes, 4 either side of the boundary */
#define STACK_VA 0x7ffff000ull
#define KEY      0x5Au

int main(void)
{
	/*
	 *   movabs rsi, MARK_VA
	 *   mov    rcx, 8
	 * loop:
	 *   mov  al,[rsi] / xor al,KEY / mov [rsi],al / inc rsi / dec rcx / jnz
	 *   jmp  MARK_VA          - lands in a page the stub wrote: HANDOFF
	 */
	static uint8_t code[] = {
		0x48,0xBE, 0xFC,0x1F,0x40,0x00,0x00,0x00,0x00,0x00,
		0x48,0xB9, 0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x8A,0x06, 0x34,KEY, 0x88,0x06,
		0x48,0xFF,0xC6, 0x48,0xFF,0xC9, 0x75,0xF2,
		0xE9, 0xD5,0x1F,0x00,0x00
	};
	static const char plain[8] = { 'S','P','A','N','-','O','K','!' };
	uint8_t data[16], got[16];
	struct kof_emu_cfg cfg = { 0 };
	struct kof_emu *e;
	enum kof_emu_stop st;
	int i;

	cfg.max_insn = 100000;
	cfg.stop_on_written_jump = 1;

	/* The marker sits at MARK_VA, which is DATA_VA + 0xffc. */
	memset(data, 0, sizeof data);
	for (i = 0; i < 8; i++)
		data[4 + i] = (uint8_t)plain[i] ^ KEY;

	e = kof_emu_new(&cfg);
	if (!e) { fail("out of memory"); return 1; }

	if (!kof_emu_map(e, CODE_VA, code, sizeof code, 0x1000,
			 KOF_EMU_R | KOF_EMU_X) ||
	    !kof_emu_map(e, DATA_VA, NULL, 0, DATA_LEN,
			 KOF_EMU_R | KOF_EMU_W) ||
	    !kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W))
		fail("map");
	if (!kof_emu_write(e, MARK_VA - 4, data, sizeof data))
		fail("seed the ciphertext");

	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);

	st = kof_emu_run(e);
	if (st != KOF_EMU_STOP_HANDOFF)
		fail("the stub did not reach the jump into what it wrote");

	/*
	 * ---- the span, unaligned, across the boundary, after the stop ------
	 * 0x401ff8 .. 0x402007: four bytes short of MARK_VA and past the end
	 * of the first page, so neither page alone can answer it.
	 */
	memset(got, 0xAA, sizeof got);
	if (!kof_emu_read(e, MARK_VA - 4, got, sizeof got))
		fail("a span across a page boundary was refused");
	else if (memcmp(got + 4, plain, 8))
		fail("a span across a page boundary came back wrong");

	/* A whole page read from an unaligned start, which is the shape the
	 * search actually uses. */
	{
		uint8_t page[0x1000];

		if (!kof_emu_read(e, DATA_VA + 0x800u, page, sizeof page))
			fail("an unaligned page-sized span was refused");
		else if (memcmp(page + (MARK_VA - (DATA_VA + 0x800u)), plain, 8))
			fail("an unaligned page-sized span came back wrong");
	}

	/* ---- and one that runs off the end answers nothing at all --------- */
	memset(got, 0xAA, sizeof got);
	if (kof_emu_read(e, DATA_VA + DATA_LEN - 8u, got, sizeof got))
		fail("a span with one end unmapped was answered");
	for (i = 0; i < 16; i++)
		if (got[i] != 0xAA)
			{ fail("a refused span still wrote to the buffer"); break; }

	kof_emu_free(e);
	printf("emu span read: cross-page, unaligned, post-stop, all-or-nothing"
	       " - %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
