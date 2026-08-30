/*
 * emu_core - the interpreter, on a stub small enough to read.
 *
 * The stub below is the shape every packer has, in twenty-odd bytes: walk a
 * buffer, undo something to each byte, jump into what you just wrote. If that
 * does not work then nothing built on top of it can, and a failure here names
 * the instruction rather than leaving it to be found in a megabyte of UPX.
 *
 * What is asserted is not "it ran" but the three things a caller depends on:
 * the plaintext comes back, the run stops for the RIGHT reason, and the pages
 * the loader wrote are not reported as pages the stub produced.
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
#define DATA_VA  0x401000ull
#define STACK_VA 0x7ffff000ull
#define KEY      0x5Au

int main(void)
{
	/*
	 *   movabs rsi, DATA_VA
	 *   movabs rcx, 16
	 * loop:
	 *   mov  al, [rsi]      8A 06
	 *   xor  al, KEY        34 5A
	 *   mov  [rsi], al      88 06
	 *   inc  rsi            48 FF C6
	 *   dec  rcx            48 FF C9
	 *   jnz  loop           75 F2
	 *   jmp  DATA_VA        E9 D9 0F 00 00
	 */
	static uint8_t code[] = {
		0x48,0xBE, 0x00,0x10,0x40,0x00,0x00,0x00,0x00,0x00,
		0x48,0xB9, 0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x8A,0x06, 0x34,KEY, 0x88,0x06,
		0x48,0xFF,0xC6, 0x48,0xFF,0xC9, 0x75,0xF2,
		0xE9, 0xD9,0x0F,0x00,0x00
	};
	static const char plain[16] = "KOFENG-EMU-OK!!";
	uint8_t cipher[16];
	/* This stub really does hand off by jumping into what it wrote, which is
	 * the case the option exists for. */
	struct kof_emu_cfg cfg = { 100000, 0, 1 };
	struct kof_emu *e;
	enum kof_emu_stop st;
	uint32_t it = 0, runs = 0;
	uint64_t va, len;
	const uint8_t *bytes;
	int found = 0, i;

	for (i = 0; i < 16; i++)
		cipher[i] = (uint8_t)plain[i] ^ KEY;

	e = kof_emu_new(&cfg);
	if (!e) { fail("out of memory"); return 1; }

	if (!kof_emu_map(e, CODE_VA, code, sizeof code, 0x1000,
			 KOF_EMU_R | KOF_EMU_X) ||
	    !kof_emu_map(e, DATA_VA, cipher, sizeof cipher, 0x1000,
			 KOF_EMU_R | KOF_EMU_W) ||
	    !kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W))
		fail("map");

	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);

	st = kof_emu_run(e);
	printf("  ran %llu insn, stopped: %s%s%s\n",
	       (unsigned long long)kof_emu_insn_count(e),
	       kof_emu_stop_name(st),
	       kof_emu_stop_detail(e)[0] ? " " : "", kof_emu_stop_detail(e));

	/*
	 * HANDOFF and not BUDGET. Reaching the end by running out of budget
	 * would mean the jump into the decrypted page was not recognised, and
	 * the one thing this emulator exists to notice is exactly that moment.
	 */
	if (st != KOF_EMU_STOP_HANDOFF)
		fail("did not stop at the jump into what it wrote");

	while (kof_emu_next_written(e, &it, &va, &bytes, &len)) {
		runs++;
		if (va <= DATA_VA && DATA_VA + 16 <= va + len &&
		    !memcmp(bytes + (DATA_VA - va), plain, 15))
			found = 1;
		/* The loader's own pages must not be in here: code was mapped,
		 * never written, and reporting it would hand the packed file
		 * back as if the stub had produced it. */
		if (va <= CODE_VA && CODE_VA < va + len)
			fail("a page only the loader touched is reported as written");
	}
	if (!found)
		fail("the decrypted bytes did not come back");
	printf("  %u written run(s), plaintext recovered: %s\n",
	       runs, found ? "yes" : "NO");

	kof_emu_free(e);
	printf("emu core: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
