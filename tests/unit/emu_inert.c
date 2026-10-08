/*
 * emu_inert - the instructions the interpreter steps over, and the one that
 * looks exactly like them and must not be stepped over.
 *
 * WHY THIS NEEDS A TEST. A junk generator emits `xchg ebx, ebx` and `mov edi,
 * edi` by the dozen, and the interpreter skips them without entering its
 * execute path - see nop_insn. The saving is small and certain; the risk is
 * that "writes a register its own value" is NOT always nothing.
 *
 * `MOV EAX, EAX` IN 64-BIT MODE ZEROES THE TOP HALF OF RAX. It is the
 * shortest way to truncate a register and compilers emit it on purpose. It is
 * spelled the same as the no-op, it decodes to the same instruction with the
 * same two operands naming the same register, and treating it as inert loses
 * thirty-two bits of a value with nothing to show that it happened.
 *
 * So both halves are asserted here: that the inert forms really are skipped
 * (by their result, which is "unchanged"), and that this one is not.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libgenome/phenotype/kofemu.h"

static int failures;

#define CODE_VA  0x400000ull
#define STACK_VA 0x7ff00000ull

/* Run a stub with RAX/RBX preset, answer RAX afterwards. */
static uint64_t run_one(unsigned bits, const uint8_t *code, unsigned n,
			uint64_t rax)
{
	struct kof_emu_cfg cfg = { 0 };
	struct kof_emu *e;
	uint64_t out;

	cfg.bits = bits;
	cfg.max_insn = 64;
	e = kof_emu_new(&cfg);
	if (!e)
		return 0;
	kof_emu_map(e, CODE_VA, code, n, 0x1000, KOF_EMU_R | KOF_EMU_X);
	kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W);
	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);
	kof_emu_set_reg(e, KOF_EMU_RAX, rax);
	(void)kof_emu_run(e);
	out = kof_emu_get_reg(e, KOF_EMU_RAX);
	kof_emu_free(e);
	return out;
}

/*
 * EACH ONE TWICE, because the skip only happens on a cache HIT - the first
 * sight of an instruction is decoded and executed like any other, and the
 * decision is recorded for the next. A loop body is what this is for, so the
 * test loops too.
 */
int main(void)
{
	/* 64-bit: mov rax, rax (REX.W) twice, then hlt. Inert, so RAX stands. */
	static const uint8_t keep64[] = {
		0x48,0x89,0xC0, 0x48,0x89,0xC0, 0xF4
	};
	/* 64-bit: mov eax, eax twice. NOT inert - the top half must go. */
	static const uint8_t trunc64[] = {
		0x89,0xC0, 0x89,0xC0, 0xF4
	};
	/* 32-bit: xchg eax, eax and mov eax, eax - both inert there. */
	static const uint8_t keep32[] = {
		0x90, 0x89,0xC0, 0x87,0xC0, 0x89,0xC0, 0xF4
	};
	const uint64_t big = 0xdeadbeefcafef00dull;
	uint64_t v;

	v = run_one(64, keep64, sizeof keep64, big);
	if (v != big) {
		printf("  FAIL mov rax,rax changed it: %#llx\n",
		       (unsigned long long)v);
		failures++;
	}
	v = run_one(64, trunc64, sizeof trunc64, big);
	if (v != (big & 0xffffffffull)) {
		printf("  FAIL mov eax,eax in 64-bit did not truncate:"
		       " %#llx\n", (unsigned long long)v);
		failures++;
	}
	v = run_one(32, keep32, sizeof keep32, 0x11223344ull);
	if (v != 0x11223344ull) {
		printf("  FAIL a 32-bit no-op changed eax: %#llx\n",
		       (unsigned long long)v);
		failures++;
	}

	printf("inert: nop and reg-to-itself skipped, 32-bit truncation in"
	       " 64-bit mode not - %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
