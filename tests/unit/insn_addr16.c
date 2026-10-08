/*
 * insn_addr16 - the address-size prefix, which is how a Windows stub reads the
 * PEB.
 *
 * WHY THIS IS A TEST AND NOT A COMMENT. A decoder rewrite that dropped the rule
 * would pass every test that only checks lengths of common code. What it covers has
 * no symptom worth the name: the instruction decodes, the run continues, and
 * the guest simply believes it is not on Windows NT. Measured on a Sality
 * sample, that cost twenty-five instructions of virus body instead of seven
 * million - and nothing anywhere said so.
 *
 * WHAT IS ASSERTED. `64 67 8B 1E 30 00` is six bytes and reads fs:0x30. That is
 * `mov ebx, fs:[0x30]` written with the 0x67 prefix, so the ModRM is decoded in
 * 16-bit addressing, where mod=0/rm=6 is a bare disp16. objdump and ndisasm
 * both agree on six bytes; a decoder that ignores the prefix for ModRM gives
 * four and drops the displacement.
 *
 * AND THE VALUE, not only the decode. The length being right means the NEXT
 * instruction is found; the displacement being right means the segment base is
 * added to the address the program asked for. A test that stopped at the
 * decode would pass with the emulator still reading page zero.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libgenome/phenotype/kofemu.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

#define TEB_VA   0x7ffe1000ull
#define PEB_VA   0x7ffe2000ull
#define CODE_VA  0x400000ull
#define STACK_VA 0x7ff00000ull

/*
 * Run a stub that reads the PEB pointer into EBX, then puts a marker in EAX so
 * the test can tell "the second instruction ran" from "the decoder swallowed
 * it". Answers EBX, and sets *reached from EAX.
 */
static uint64_t peb_read(const uint8_t *code, unsigned n, int *reached)
{
	struct kof_emu_cfg cfg = { 0 };
	struct kof_emu *e;
	uint8_t teb[0x1000];
	uint64_t ebx;

	cfg.bits = 32;
	cfg.max_insn = 64;
	e = kof_emu_new(&cfg);
	if (!e)
		return 0;
	memset(teb, 0, sizeof teb);
	teb[0x30] = 0x00; teb[0x31] = 0x20; teb[0x32] = 0xfe; teb[0x33] = 0x7f;

	kof_emu_map(e, CODE_VA, code, n, 0x1000, KOF_EMU_R | KOF_EMU_X);
	kof_emu_map(e, TEB_VA, teb, sizeof teb, 0x2000, KOF_EMU_R | KOF_EMU_W);
	kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W);
	/* the decoder's segment ids: ES, CS, SS, DS, FS, GS - FS is 4, which is
	 * where a 32-bit Windows thread keeps its TEB. */
	kof_emu_set_seg_base(e, 4, TEB_VA);
	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);
	(void)kof_emu_run(e);
	ebx = kof_emu_get_reg(e, KOF_EMU_RBX);
	*reached = kof_emu_get_reg(e, KOF_EMU_RAX) == 0x5aa5u;
	kof_emu_free(e);
	return ebx;
}

int main(void)
{
	/* 64 67 8B 1E 3000   mov ebx, fs:[0x30]   -- 16-bit addressing
	 * B8 A5 5A 00 00     mov eax, 0x5aa5      -- the marker
	 * F4                 hlt */
	static const uint8_t pref[] = {
		0x64,0x67,0x8B,0x1E,0x30,0x00, 0xB8,0xA5,0x5A,0x00,0x00, 0xF4
	};
	/* The same read with no prefix, which always worked: the control. */
	static const uint8_t plain[] = {
		0x64,0x8B,0x1D,0x30,0x00,0x00,0x00, 0xB8,0xA5,0x5A,0x00,0x00, 0xF4
	};
	int reached = 0;
	uint64_t v;

	v = peb_read(pref, sizeof pref, &reached);
	if (v != PEB_VA)
		fail("mov ebx, fs:[0x30] with the 0x67 prefix read the wrong address");
	if (!reached)
		fail("the instruction after it was not reached - its length is wrong");

	v = peb_read(plain, sizeof plain, &reached);
	if (v != PEB_VA)
		fail("mov ebx, fs:[0x30] without the prefix read the wrong address");
	if (!reached)
		fail("the instruction after the unprefixed read was not reached");

	printf("addr16: fs:[0x30] through the 0x67 prefix, value and length - %s\n",
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
