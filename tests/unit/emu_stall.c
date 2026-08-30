/*
 * emu_stall - the two ways a packer wastes an analyst's budget instead of
 * defeating it, and what the interpreter does about each.
 *
 * Neither is an exploit and neither needs to be clever. A stub that sleeps
 * thirty seconds before it unpacks costs a person nothing to sit through and
 * costs an automated scan its whole time budget; a stub that spins on the cycle
 * counter until a million ticks have passed costs a real CPU a millisecond and
 * costs an interpreter a million instructions. Both are cheap to write and both
 * work, unless the clock the guest reads is under the emulator's control.
 *
 * So it is: the clock advances with instructions retired, which keeps the RATIO
 * between two readings honest - a timing check that measures real work still
 * gets a believable answer - and a delay LOOP, recognised by the guest asking
 * the time repeatedly having done nothing in between, is granted its wait in
 * jumps. A sleep is granted in full and waited for not at all.
 *
 * What is asserted is that both stubs finish, that the loop finishes in far
 * fewer instructions than the delay it asked for, and that the sleep actually
 * MOVED the clock - a sleep that returned instantly and left the time alone is
 * a louder signal to a packer than a slow machine.
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
#define DATA_VA   0x401000ull
#define STACK_VA  0x7ffff000ull
#define SPIN_FOR  0x00100000u          /* ticks the loop insists on */
#define SLEEP_SEC 100u

int main(void)
{
	/*
	 *   rdtsc / mov rbx, rax
	 * L: rdtsc / sub rax, rbx / cmp rax, SPIN_FOR / jb L
	 *   nanosleep(DATA_VA, NULL)
	 *   clock_gettime(CLOCK_MONOTONIC, DATA_VA + 16)
	 *   exit(0)
	 */
	static uint8_t code[] = {
		0x0F,0x31,                               /*  0 rdtsc          */
		0x48,0x89,0xC3,                          /*  2 mov rbx, rax   */
		0x0F,0x31,                               /*  5 rdtsc          */
		0x48,0x29,0xD8,                          /*  7 sub rax, rbx   */
		0x48,0x3D, 0,0,0,0,                      /* 10 cmp rax, imm32 */
		0x72,0xF3,                               /* 16 jb -13         */
		0x48,0xBF, 0,0,0,0,0,0,0,0,              /* 18 movabs rdi, TS */
		0x48,0x31,0xF6,                          /* 28 xor rsi, rsi   */
		0x48,0xC7,0xC0, 0x23,0,0,0,              /* 31 mov rax, 35    */
		0x0F,0x05,                               /* 38 syscall        */
		0x48,0xC7,0xC7, 0x01,0,0,0,              /* 40 mov rdi, 1     */
		0x48,0xBE, 0,0,0,0,0,0,0,0,              /* 47 movabs rsi,OUT */
		0x48,0xC7,0xC0, 0xE4,0,0,0,              /* 57 mov rax, 228   */
		0x0F,0x05,                               /* 64 syscall        */
		0x48,0x31,0xFF,                          /* 66 xor rdi, rdi   */
		0x48,0xC7,0xC0, 0x3C,0,0,0,              /* 69 mov rax, 60    */
		0x0F,0x05                                /* 76 syscall        */
	};
	uint64_t ts[2] = { SLEEP_SEC, 0 }, out[2] = { 0, 0 };
	struct kof_emu_cfg cfg = { 2000000, 0, 0 };
	struct kof_emu *e;
	enum kof_emu_stop st;
	uint64_t insn;
	unsigned k;

	memcpy(code + 12, &(uint32_t){ SPIN_FOR }, 4);
	memcpy(code + 20, &(uint64_t){ DATA_VA }, 8);
	memcpy(code + 49, &(uint64_t){ DATA_VA + 16u }, 8);

	e = kof_emu_new(&cfg);
	if (!e) { fail("out of memory"); return 1; }
	if (!kof_emu_map(e, CODE_VA, code, sizeof code, 0x1000,
			 KOF_EMU_R | KOF_EMU_X) ||
	    !kof_emu_map(e, DATA_VA, (const uint8_t *)ts, sizeof ts, 0x1000,
			 KOF_EMU_R | KOF_EMU_W) ||
	    !kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W))
		fail("map");
	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);

	st = kof_emu_run(e);
	insn = kof_emu_insn_count(e);
	printf("  chờ %u tick, ngủ %u s -> %llu lệnh, dừng=%s\n",
	       SPIN_FOR, SLEEP_SEC, (unsigned long long)insn,
	       kof_emu_stop_name(st));

	if (st != KOF_EMU_STOP_EXIT)
		fail("the stub did not reach its own exit");
	/*
	 * The loop asked for SPIN_FOR ticks and the clock runs at about a tick
	 * an instruction, so without the jumps this cannot finish in less than
	 * SPIN_FOR instructions. A generous fraction of that is still proof.
	 */
	if (insn >= SPIN_FOR / 8u)
		fail("the delay loop was waited out rather than recognised");

	if (!kof_emu_read(e, DATA_VA + 16u, out, sizeof out))
		fail("the guest's clock reading could not be read back");
	printf("  đồng hồ sau khi ngủ: %llu s %llu ns\n",
	       (unsigned long long)out[0], (unsigned long long)out[1]);
	if (out[0] < SLEEP_SEC)
		fail("the sleep returned without the clock having moved");

	/* Nothing here should have needed a syscall this build lacks. */
	{
		uint32_t un[KOF_EMU_UNKSYS];

		for (k = kof_emu_unknown_syscalls(e, un, KOF_EMU_UNKSYS); k--; )
			printf("  syscall bị từ chối: %u\n", un[k]);
	}

	kof_emu_free(e);
	printf("emu stall: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
