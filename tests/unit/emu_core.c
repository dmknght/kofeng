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

/*
 * EVERY SYSCALL A STUB ASKS BEFORE IT UNPACKS MUST BE ANSWERED, and -ENOSYS is
 * the one answer that is never right.
 *
 * None of these move a byte of payload. They are what a packer asks FIRST -
 * who am I running as, what kernel is this, how much memory is here, where am
 * I on disk - and on a real Linux none of them fails. A refusal is therefore
 * not a missing feature but a SIGNAL: the stub learns it is not on a machine,
 * and the interesting ones stop there. That is a failure mode with no symptom
 * except a payload that never appears, which is why it is asserted rather than
 * left to be noticed.
 *
 * The call is made with plausible arguments and the RESULT is not checked -
 * only that it is not -ENOSYS. What each one should say is the dispatcher's
 * business; that it says anything at all is this test's.
 */
static void syscalls_answered(void)
{
	static const struct { unsigned nr; const char *name; } want[] = {
		{ 63, "uname" },      { 102, "getuid" },   { 107, "geteuid" },
		{ 104, "getgid" },    { 108, "getegid" },  { 110, "getppid" },
		{ 99, "sysinfo" },    { 100, "times" },    { 229, "clock_getres" },
		{ 79, "getcwd" },     { 157, "prctl" },    { 135, "personality" },
		{ 97, "getrlimit" },  { 160, "setrlimit" },{ 21, "access" },
		{ 269, "faccessat" }, { 439, "faccessat2" },
		{ 267, "readlinkat" },{ 4, "stat" },       { 6, "lstat" },
		{ 137, "statfs" },    { 138, "fstatfs" },  { 32, "dup" },
		{ 33, "dup2" },       { 292, "dup3" },     { 72, "fcntl" },
		{ 20, "writev" },     { 19, "readv" },     { 18, "pwrite64" },
		{ 22, "pipe" },       { 293, "pipe2" },    { 25, "mremap" },
		/* The ones that were always here, so a rewrite of the
		 * dispatcher cannot quietly drop them either. */
		{ 9, "mmap" },        { 10, "mprotect" },  { 12, "brk" },
		{ 35, "nanosleep" },  { 228, "clock_gettime" },
		{ 319, "memfd_create" }
	};
	const uint64_t buf = 0x410000ull;
	unsigned i, refused = 0;

	for (i = 0; i < sizeof want / sizeof want[0]; i++) {
		uint8_t code[64];
		unsigned n = 0;
		struct kof_emu_cfg cfg = { 0 };

		cfg.max_insn = 100000;
		struct kof_emu *e = kof_emu_new(&cfg);
		uint64_t ret;

		if (!e) { fail("out of memory"); return; }
		/* mov rax,nr / mov rdi,buf / mov rsi,buf+0x800 /
		 * mov rdx,buf+0x1000 / mov r10,4096 / syscall / hlt */
		code[n++] = 0x48; code[n++] = 0xC7; code[n++] = 0xC0;
		memcpy(code + n, &want[i].nr, 4); n += 4;
		code[n++] = 0x48; code[n++] = 0xBF;
		memcpy(code + n, &(uint64_t){ buf }, 8); n += 8;
		code[n++] = 0x48; code[n++] = 0xBE;
		memcpy(code + n, &(uint64_t){ buf + 0x800u }, 8); n += 8;
		code[n++] = 0x48; code[n++] = 0xBA;
		memcpy(code + n, &(uint64_t){ buf + 0x1000u }, 8); n += 8;
		code[n++] = 0x49; code[n++] = 0xC7; code[n++] = 0xC2;
		memcpy(code + n, &(uint32_t){ 4096u }, 4); n += 4;
		code[n++] = 0x0F; code[n++] = 0x05;
		code[n++] = 0xF4;                       /* hlt: stop here */

		kof_emu_map(e, CODE_VA, code, n, 0x1000,
			    KOF_EMU_R | KOF_EMU_X);
		kof_emu_map(e, buf, NULL, 0, 0x3000, KOF_EMU_R | KOF_EMU_W);
		kof_emu_map(e, STACK_VA, NULL, 0, 0x1000,
			    KOF_EMU_R | KOF_EMU_W);
		kof_emu_set_rip(e, CODE_VA);
		kof_emu_set_reg(e, KOF_EMU_RSP, STACK_VA + 0x800);
		(void)kof_emu_run(e);
		ret = kof_emu_get_reg(e, KOF_EMU_RAX);
		if ((int64_t)ret == -38) {              /* ENOSYS */
			printf("  FAIL %s answered -ENOSYS\n", want[i].name);
			failures++;
			refused++;
		}
		kof_emu_free(e);
	}
	printf("  %zu syscall(s) a stub asks first, %u refused\n",
	       sizeof want / sizeof want[0], refused);
}
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
	struct kof_emu_cfg cfg = { 0 };
	struct kof_emu *e;
	enum kof_emu_stop st;
	uint32_t it = 0, runs = 0;
	uint64_t va, len;

	cfg.max_insn = 100000;
	cfg.stop_on_written_jump = 1;
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

	syscalls_answered();

	printf("emu core: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
