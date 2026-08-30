/*
 * emu_unpack - the two things that made a real packer work, on a stub that
 * fits on a screen.
 *
 * Both were found the same way, by running UPX and watching it fail quietly:
 *
 *   A stub reads itself by MAPPING its own file, not by calling read(). Served
 *   anonymous zeroes instead, UPX's decompressor walked an all-zero ELF header,
 *   found e_phnum == 0, skipped its entire load and returned a nonsense entry
 *   point - no error anywhere, just a wrong answer thirty thousand
 *   instructions later.
 *
 *   The payload has to be SNAPSHOTTED WHERE IT IS FINISHED, at the mprotect
 *   that makes it executable. Reading the same addresses when the run ends can
 *   find anything at all: the unpacked PyInstaller bootloader ran, opened a
 *   file and mapped another image over its own text, so the final memory held
 *   the packed header again.
 *
 * So this stub maps its own file, decrypts what it read, makes it executable,
 * and then scribbles over it - and the test asserts the plaintext is in the
 * snapshot and NOT in the final memory. Get either half wrong and one of the
 * two assertions below fails.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofemu/kofemu.h"

static int failures;

/* No memmem: it needs _GNU_SOURCE and this has to build the same everywhere. */
static int has(const uint8_t *hay, uint64_t n, const void *needle, unsigned m)
{
	uint64_t i;

	if (n < m)
		return 0;
	for (i = 0; i + m <= n; i++)
		if (!memcmp(hay + i, needle, m))
			return 1;
	return 0;
}

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

#define CODE_VA   0x400000ull
#define STACK_VA  0x7ffff000ull
#define SELF_OFF  0x1000u          /* where the ciphertext sits in the file */
#define KEY       0x5Au
#define N         16u

int main(void)
{
	/*
	 *   mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE, 3, SELF_OFF)
	 *   decrypt N bytes in place, xor KEY
	 *   mprotect(base, 0x1000, PROT_READ|PROT_EXEC)
	 *   overwrite those N bytes with 0xCC
	 *   exit(0)
	 */
	static uint8_t code[] = {
		0x48,0x31,0xFF,                          /* xor  rdi, rdi      */
		0x48,0xC7,0xC6, 0x00,0x10,0x00,0x00,     /* mov  rsi, 0x1000   */
		0x48,0xC7,0xC2, 0x03,0x00,0x00,0x00,     /* mov  rdx, 3        */
		0x49,0xC7,0xC2, 0x02,0x00,0x00,0x00,     /* mov  r10, 2        */
		0x49,0xC7,0xC0, 0x03,0x00,0x00,0x00,     /* mov  r8,  3        */
		0x49,0xC7,0xC1, 0x00,0x10,0x00,0x00,     /* mov  r9,  0x1000   */
		0x48,0xC7,0xC0, 0x09,0x00,0x00,0x00,     /* mov  rax, 9        */
		0x0F,0x05,                               /* syscall            */
		0x48,0x89,0xC3,                          /* mov  rbx, rax      */

		0x48,0x89,0xC6,                          /* mov  rsi, rax      */
		0x48,0xC7,0xC1, N,0x00,0x00,0x00,        /* mov  rcx, N        */
		0x8A,0x06,                               /* mov  al, [rsi]     */
		0x34,KEY,                                /* xor  al, KEY       */
		0x88,0x06,                               /* mov  [rsi], al     */
		0x48,0xFF,0xC6,                          /* inc  rsi           */
		0x48,0xFF,0xC9,                          /* dec  rcx           */
		0x75,0xF2,                               /* jnz  -14           */

		0x48,0x89,0xDF,                          /* mov  rdi, rbx      */
		0x48,0xC7,0xC6, 0x00,0x10,0x00,0x00,     /* mov  rsi, 0x1000   */
		0x48,0xC7,0xC2, 0x05,0x00,0x00,0x00,     /* mov  rdx, 5        */
		0x48,0xC7,0xC0, 0x0A,0x00,0x00,0x00,     /* mov  rax, 10       */
		0x0F,0x05,                               /* syscall            */

		0xFC,                                    /* cld                */
		0x48,0x89,0xDF,                          /* mov  rdi, rbx      */
		0x48,0xC7,0xC1, N,0x00,0x00,0x00,        /* mov  rcx, N        */
		0xB0,0xCC,                               /* mov  al, 0xCC      */
		0xF3,0xAA,                               /* rep  stosb         */

		0x48,0x31,0xFF,                          /* xor  rdi, rdi      */
		0x48,0xC7,0xC0, 0x3C,0x00,0x00,0x00,     /* mov  rax, 60       */
		0x0F,0x05                                /* syscall            */
	};
	static const char plain[N] = "KOFENG-UNPACK-K";
	static uint8_t self[SELF_OFF + 0x1000];
	struct kof_emu_cfg cfg = { 100000, 0, 0 };
	struct kof_emu *e;
	enum kof_emu_stop st;
	uint32_t it;
	uint64_t va, len;
	const uint8_t *bytes;
	int in_snapshot = 0, in_final = 0, snaps = 0;
	unsigned i;

	for (i = 0; i < N; i++)
		self[SELF_OFF + i] = (uint8_t)plain[i] ^ KEY;

	e = kof_emu_new(&cfg);
	if (!e) { fail("out of memory"); return 1; }

	if (!kof_emu_map(e, CODE_VA, code, sizeof code, 0x1000,
			 KOF_EMU_R | KOF_EMU_X) ||
	    !kof_emu_map(e, STACK_VA, NULL, 0, 0x1000, KOF_EMU_R | KOF_EMU_W))
		fail("map");
	kof_emu_set_self(e, self, sizeof self);
	kof_emu_set_rip(e, CODE_VA);
	kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);

	st = kof_emu_run(e);
	printf("  ran %llu insn, stopped: %s%s%s\n",
	       (unsigned long long)kof_emu_insn_count(e),
	       kof_emu_stop_name(st),
	       kof_emu_stop_detail(e)[0] ? " " : "", kof_emu_stop_detail(e));
	if (st != KOF_EMU_STOP_EXIT)
		fail("the stub did not run to its own exit");

	for (it = 0; kof_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		snaps++;
		if (has(bytes, len, plain, N))
			in_snapshot = 1;
	}
	for (it = 0; kof_emu_next_written(e, &it, &va, &bytes, &len); )
		if (has(bytes, len, plain, N))
			in_final = 1;

	printf("  %d snapshot(s); plaintext in snapshot: %s, still in memory at "
	       "the end: %s\n", snaps, in_snapshot ? "yes" : "NO",
	       in_final ? "yes" : "no");

	/* Without a file-backed mmap the stub decrypts zeroes and neither of
	 * these can hold; without the snapshot only the second one does. */
	if (!in_snapshot)
		fail("the payload was not caught at the mprotect that made it "
		     "executable");
	if (in_final)
		fail("the stub did not overwrite its payload, so this proves "
		     "nothing - check the stub, not the emulator");

	kof_emu_free(e);
	printf("emu unpack: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
