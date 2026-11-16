/*
 * emu_only_force.c - KOF_EMU_ONLY runs the interpreter on an object the entropy gate refuses, and the FPU
 * GetPC of an msfvenom-style x86 encoder works under it (EMU-ONLY-1 and EMU-FOP-1, fixed 2026-11-15).
 *
 * The object is constructed here (no sample bytes): an ELF64 x86-64 executable of 512 bytes, one RWX PT_LOAD,
 * whose code is the shape of an x86 encoder's head -
 *
 *     fldz ; fnstenv [rsp-0xc] ; pop rdx            the GetPC: rdx = FIP = the fldz's address
 *     xor ecx,ecx ; mov cl,0x20
 *     L: xor [rdx+0x40],eax ; loop L                 32 stores into the image, through rdx
 *     mov eax,60 ; xor edi,edi ; syscall              exit
 *
 * Small and low-entropy, so the gate (emu_unpack_gate.c: DENSE_MIN 512 executable bytes at 7.5 bits per byte)
 * refuses it under AUTO. Before the fix ONLY ran 0 instructions (the generic module was filtered out and the run
 * was not forced), and with the gate bypassed the run stopped after 7 instructions because FNSTENV reported FOP
 * in the dword @16, so the popped rdx was 0x05c?00000400078 and the first store was refused.
 * Why the old tests missed it: (b) no test scanned a small object under ONLY, and the x87 tests compared FOP
 * with a host that also reported it on the machine they were written on.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"

static int failures;

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16)); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }

static uint32_t build(uint8_t *f)
{
	static const uint8_t code[] = {
		0xd9, 0xee,                     /* fldz */
		0xd9, 0x74, 0x24, 0xf4,         /* fnstenv [rsp-0xc] */
		0x5a,                           /* pop rdx */
		0x31, 0xc9,                     /* xor ecx,ecx */
		0xb1, 0x20,                     /* mov cl,0x20 */
		0x31, 0x42, 0x40,               /* L: xor [rdx+0x40],eax */
		0xe2, 0xfb,                     /* loop L */
		0xb8, 0x3c, 0x00, 0x00, 0x00,   /* mov eax,60 */
		0x31, 0xff,                     /* xor edi,edi */
		0x0f, 0x05,                     /* syscall */
	};
	const uint32_t n = 512u;

	memset(f, 0, n);
	memcpy(f, "\x7f" "ELF", 4);
	f[4] = 2; f[5] = 1; f[6] = 1;
	put16(f + 16, 2);                       /* ET_EXEC */
	put16(f + 18, 62);                      /* x86-64 */
	put32(f + 20, 1);
	put64(f + 24, 0x400078);                /* entry */
	put64(f + 32, 64);                      /* phoff */
	put16(f + 52, 64);
	put16(f + 54, 56);
	put16(f + 56, 1);
	put32(f + 64, 1);                       /* PT_LOAD */
	put32(f + 68, 7);                       /* RWX */
	put64(f + 72, 0);
	put64(f + 80, 0x400000);
	put64(f + 88, 0x400000);
	put64(f + 96, n);
	put64(f + 104, n);
	put64(f + 112, 0x1000);
	memcpy(f + 0x78, code, sizeof code);
	return n;
}

static uint64_t run(kof_engine *eng, const uint8_t *f, uint32_t n, uint32_t emu_use)
{
	kof_scanner *sc = kscan_new(eng);
	struct kof_scan_option o;
	uint64_t insn;

	if (!sc)
		return ~(uint64_t)0;
	memset(&o, 0, sizeof o);
	o.emu_use = emu_use;
	(void)kscan_bytes(sc, f, n, "emu_only_force", &o, NULL, NULL);
	insn = kscan_stats(sc)->emu_insn;
	kscan_free(sc);
	return insn;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	static uint8_t f[512];
	uint32_t n = build(f);
	kof_engine *eng = keng_open(db);
	uint64_t a, b;

	if (!eng) {
		printf("emu_only_force: cannot open %s\n", db);
		return 2;
	}
	a = run(eng, f, n, KOF_EMU_AUTO);
	b = run(eng, f, n, KOF_EMU_ONLY);
	/* AUTO stays gated: the object is small and plain, nothing vouches for a run. */
	if (a != 0) {
		printf("  FAIL AUTO ran %llu instruction(s) on an object the gate refuses\n", (unsigned long long)a);
		failures++;
	}
	/* ONLY runs it, and the GetPC works: 5 setup + 32 x 2 loop + exit >= 70 instructions. */
	if (b < 70) {
		printf("  FAIL ONLY ran %llu instruction(s); the GetPC loop needs at least 70\n", (unsigned long long)b);
		failures++;
	}
	keng_close(eng);
	printf(failures ? "emu_only_force: %d failure(s)\n" : "emu_only_force: ok%.0d\n", failures);
	return failures ? 1 : 0;
}
