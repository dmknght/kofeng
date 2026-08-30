/*
 * emu_gate - who gets emulated, and what happens when the header is unusable.
 *
 * Two questions, and they fail in opposite directions:
 *
 *   The GATE decides whether an object is worth a budget. Every clean file it
 *   selects is a scan made slower for nothing, so the threshold is measured
 *   rather than chosen - 7.5 bits per byte over the executable segments, which
 *   selects nothing at all across 1 246 clean binaries here. A test that only
 *   proved dense files are selected would not notice the day plain ones are
 *   selected too, so both directions are asserted.
 *
 *   The FAIL-SAFE decides what to do when the program header table cannot be
 *   read. This is the case every other module gives up on - a static unpacker
 *   needs structure and there is none - and it is also the case that is easiest
 *   to get wrong silently, because "no image built" and "an image built at the
 *   wrong address" both come back as "nothing recovered". So the object here
 *   has a stub that leaves a mark, and the test looks for the mark.
 *
 * The ELF files are built in memory. Reading them from disk would test the
 * fixture generator as much as the gate, and a header this deliberately broken
 * is not something a compiler will emit on request.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofparsers/binaries/elf_parse.h"
#include "../../libkofeng/kofunpack/emu_unpack.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

#define EHDR   64u
#define PHDR   56u
#define IMG    0x400000ull
#define BODY   0x1000u                 /* file offset of the segment body */
#define FSIZE  (BODY + 0x1000u)

static void w16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void w32(uint8_t *p, uint32_t v) { unsigned i; for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (i * 8)); }
static void w64(uint8_t *p, uint64_t v) { unsigned i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8)); }

/*
 * One PT_LOAD, read and execute, covering the whole file. `phoff_past_eof`
 * writes a program header offset beyond the end, which is what a packer that
 * reused those bytes leaves behind and what the fail-safe exists for.
 */
static void build(uint8_t *f, uint64_t entry, int phoff_past_eof)
{
	uint8_t *ph = f + EHDR;

	memset(f, 0, FSIZE);
	memcpy(f, "\177ELF\2\1\1", 7);
	w16(f + 0x10, 2);              /* ET_EXEC   */
	w16(f + 0x12, 0x3e);           /* EM_X86_64 */
	w32(f + 0x14, 1);
	w64(f + 0x18, entry);
	w64(f + 0x20, phoff_past_eof ? FSIZE + 0x10000u : EHDR);
	w16(f + 0x34, EHDR);
	w16(f + 0x36, PHDR);
	w16(f + 0x38, 1);
	w16(f + 0x3a, 64);

	w32(ph + 0x00, 1);             /* PT_LOAD        */
	w32(ph + 0x04, 4 | 1);         /* PF_R | PF_X    */
	w64(ph + 0x08, 0);
	w64(ph + 0x10, IMG);
	w64(ph + 0x18, IMG);
	w64(ph + 0x20, FSIZE);
	w64(ph + 0x28, FSIZE);
	w64(ph + 0x30, 0x1000);
}

static enum kof_emu_unp_why gate_of(const uint8_t *f)
{
	struct kof_elf_info info;
	struct kof_obj_ctx ctx;

	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	if (!kof_elf_parse(kof_buf_make(f, FSIZE), &info, &ctx))
		return KOF_EMU_UNP_NO;
	return kof_emu_unp_gate(&ctx, &info, f, FSIZE);
}

int main(void)
{
	static uint8_t f[FSIZE];
	static const char plain[8] = "KOF-EMU";
	/*
	 *   movabs rsi, IMG + BODY + 0x40
	 *   movabs rcx, 8
	 *   xor byte at rsi with 0x5A, eight times
	 *   exit(0)
	 */
	static uint8_t stub[] = {
		0x48,0xBE, 0,0,0,0,0,0,0,0,
		0x48,0xB9, 0x08,0,0,0,0,0,0,0,
		0x8A,0x06, 0x34,0x5A, 0x88,0x06,
		0x48,0xFF,0xC6, 0x48,0xFF,0xC9, 0x75,0xF2,
		0x48,0x31,0xFF, 0x48,0xC7,0xC0, 0x3C,0,0,0, 0x0F,0x05
	};
	struct kof_elf_info info;
	struct kof_obj_ctx ctx;
	struct kof_emu_unp_report rep;
	struct kof_emu *e;
	enum kof_emu_unp_why why;
	uint32_t seed = 0x1234567u, i;
	uint32_t it;
	uint64_t va, len;
	const uint8_t *bytes;
	int found = 0;

	/* 1. A plain object: ordinary code, and nothing to emulate. */
	build(f, IMG + BODY, 0);
	memset(f + BODY, 0x90, 0x1000);
	why = gate_of(f);
	printf("  đặc? không (mã thường)         -> %d\n", (int)why);
	if (why != KOF_EMU_UNP_NO)
		fail("a segment of NOPs was selected for emulation");

	/*
	 * 2. The same object with a dense executable segment.
	 *
	 * Filled from just past the headers rather than only the second page:
	 * the segment covers the whole file, so leaving four kilobytes of
	 * zeroes inside it halves the measured density. That is not an artefact
	 * of the test - it is how the threshold behaves on a real packed
	 * binary, whose executable segment carries a plain stub alongside the
	 * compressed payload, and it is why 7.5 rather than 8 is the number.
	 */
	build(f, IMG + BODY, 0);
	for (i = 0x100u; i < FSIZE; i++) {
		seed = seed * 1103515245u + 12345u;
		f[i] = (uint8_t)(seed >> 16);
	}
	why = gate_of(f);
	printf("  đặc? có (entropy cao)          -> %d\n", (int)why);
	if (why != KOF_EMU_UNP_WHY_DENSE)
		fail("a dense executable segment was not selected");

	/* 3. The fail-safe: the program header table is not there to read. */
	build(f, IMG + BODY, 1);
	memcpy(f + BODY, stub, sizeof stub);
	w64(f + BODY + 2, IMG + BODY + 0x40);
	for (i = 0; i < sizeof plain; i++)
		f[BODY + 0x40 + i] = (uint8_t)plain[i] ^ 0x5Au;

	why = gate_of(f);
	printf("  header không đọc được          -> %d\n", (int)why);
	if (why != KOF_EMU_UNP_WHY_BROKEN)
		fail("an unreadable program header table was not recognised");

	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	kof_elf_parse(kof_buf_make(f, FSIZE), &info, &ctx);
	e = kof_emu_unp_run(f, FSIZE, &info, 100000, 0, &rep);
	if (!e) {
		fail("no process image could be built from a broken header");
		printf("emu gate: FAILED\n");
		return 1;
	}
	printf("  chạy dự phòng: entry=%#llx%s %llu lệnh, dừng=%s\n",
	       (unsigned long long)rep.entry, rep.improvised ? " (đoán)" : "",
	       (unsigned long long)rep.insn, kof_emu_stop_name(rep.stop));

	for (it = 0; kof_emu_next_written(e, &it, &va, &bytes, &len); ) {
		uint64_t k;

		for (k = 0; len >= sizeof plain && k + sizeof plain <= len; k++)
			if (!memcmp(bytes + k, plain, sizeof plain - 1)) {
				found = 1;
				break;
			}
	}
	/*
	 * With no program header table there is no segment to map, so this only
	 * works if the object was mapped flat and the entry was resolved
	 * against that map. Recovering the mark proves both.
	 */
	if (rep.stop != KOF_EMU_STOP_EXIT)
		fail("the fallback image did not run the stub to its exit");
	if (!found)
		fail("the stub ran but what it decrypted was not recovered");

	kof_emu_free(e);
	printf("emu gate: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
