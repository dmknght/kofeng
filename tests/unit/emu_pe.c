/*
 * emu_pe.c - a PE whose entry point is an XOR decoder, run through the
 * emulator, checked for the bytes it decoded.
 *
 * WHY A HAND-BUILT FILE AND NOT A SAMPLE
 *
 * The claim under test is the one emu_unpack.h makes: that a PE is worth
 * running with no Windows API layer behind it, because a stub's decoding half
 * is arithmetic and needs none. A real packed sample would test that claim and
 * a dozen other things at once, and it would have to be checked in - so the
 * test would only run where somebody had put the file, which is the same as
 * not running.
 *
 * Everything here is therefore built from bytes: a PE32+ with two sections, an
 * entry point that XORs a buffer in .data with a constant, and a marker to
 * find afterwards. The stub touches no import, no PEB and no syscall, which is
 * precisely the class the header says this reaches. If the marker comes back,
 * the image was built, the entry was resolved, the stack held, the instructions
 * were interpreted and the written pages were harvested - the whole path, with
 * one assertion.
 *
 * It also pins the SHAPE of the stop. The stub ends in `ret`, and the return
 * address build_stack_pe leaves is deliberately unmapped, so a correct run
 * stops by faulting at exactly that address. A run that stops somewhere else
 * went somewhere it should not have.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kofmod/pe.h>
#include <kofmod/kofsig.h>
#include "../../libkofeng/analyzer/parsers/binaries/pe_parse.h"
#include "../../libkofeng/extractor/unpack/emu_unpack.h"
#include "../../libkofeng/kofeng.h"

#define BASE      0x0000000140000000ull
#define HDR_LEN   0x400u
#define TEXT_RVA  0x1000u
#define DATA_RVA  0x2000u
#define TEXT_OFF  0x400u
#define DATA_OFF  0x600u
#define TEXT_RAW  0x200u
/*
 * A FULL PAGE OF PAYLOAD, not a token forty bytes.
 *
 * The harvest in objctx.c only hands a written region over when emu_novel
 * agrees it is new, and emu_novel samples the region at spread positions and
 * SKIPS any probe that is all zero. A short payload in an otherwise zero page
 * is therefore invisible to it - every probe but the first lands on nothing -
 * so a fixture built that way passes this test and produces no child object in
 * a real scan. Measured: at 0x200 the scanner saw one object, at 0x1000 it saw
 * two. The size is part of what makes this representative.
 */
#define DATA_RAW  0x1000u
#define KEY       0x5Au

/* Long enough that finding it cannot be chance, and containing no byte run a
 * zeroed page could produce. */
static const char MARKER[] = "KOFENG-UNPACKED-PAYLOAD-MARKER-0123456789";

static int failures;

static void ck(int ok, const char *what)
{
	if (!ok) {
		printf("  FAIL: %s\n", what);
		failures++;
	}
}

static void w16(unsigned char *p, unsigned v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
}

static void w32(unsigned char *p, unsigned long v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

static void w64(unsigned char *p, unsigned long long v)
{
	w32(p, (unsigned long)(v & 0xffffffffu));
	w32(p + 4, (unsigned long)(v >> 32));
}

static unsigned char *build(size_t *out_len)
{
	size_t len = DATA_OFF + DATA_RAW;
	unsigned char *f = calloc(1, len);
	unsigned char *nt, *sec, *code, *data;
	unsigned char payload[DATA_RAW];
	unsigned i, mlen = (unsigned)strlen(MARKER) + 1u, n = DATA_RAW;

	if (!f)
		return NULL;

	f[0] = 'M';
	f[1] = 'Z';
	w32(f + 0x3c, 0x40);              /* e_lfanew */

	nt = f + 0x40;
	nt[0] = 'P'; nt[1] = 'E'; nt[2] = 0; nt[3] = 0;
	w16(nt + 4, 0x8664);              /* Machine: AMD64            */
	w16(nt + 6, 2);                   /* NumberOfSections          */
	w16(nt + 20, 0xF0);               /* SizeOfOptionalHeader      */
	w16(nt + 22, 0x0022);             /* EXECUTABLE | LARGE_ADDRESS */

	{
		unsigned char *o = nt + 24;

		w16(o + 0, 0x20b);        /* PE32+                     */
		w32(o + 16, TEXT_RVA);    /* AddressOfEntryPoint       */
		w64(o + 24, BASE);        /* ImageBase                 */
		w32(o + 32, 0x1000);      /* SectionAlignment          */
		w32(o + 36, 0x200);       /* FileAlignment             */
		w32(o + 56, 0x3000);      /* SizeOfImage               */
		w32(o + 60, HDR_LEN);     /* SizeOfHeaders             */
		w16(o + 68, 3);           /* Subsystem: console        */
		w32(o + 108, 16);         /* NumberOfRvaAndSizes       */
	}

	sec = nt + 24 + 0xF0;
	memcpy(sec, ".text\0\0", 8);
	w32(sec + 8,  TEXT_RAW);          /* VirtualSize               */
	w32(sec + 12, TEXT_RVA);
	w32(sec + 16, TEXT_RAW);          /* SizeOfRawData             */
	w32(sec + 20, TEXT_OFF);
	w32(sec + 36, 0x60000020u);       /* CODE | EXECUTE | READ     */

	memcpy(sec + 40, ".data\0\0", 8);
	w32(sec + 48, DATA_RAW);
	w32(sec + 52, DATA_RVA);
	w32(sec + 56, DATA_RAW);
	w32(sec + 60, DATA_OFF);
	w32(sec + 76, 0xC0000040u);       /* INITIALIZED | READ | WRITE */

	/*
	 *      mov rsi, BASE + DATA_RVA
	 *      mov ecx, n
	 *   L: xor byte [rsi], KEY
	 *      inc rsi
	 *      dec ecx
	 *      jnz L
	 *      ret
	 */
	code = f + TEXT_OFF;
	i = 0;
	code[i++] = 0x48; code[i++] = 0xBE;
	w64(code + i, BASE + DATA_RVA); i += 8;
	code[i++] = 0xB9;
	w32(code + i, n); i += 4;
	code[i++] = 0x80; code[i++] = 0x36; code[i++] = KEY;
	code[i++] = 0x48; code[i++] = 0xFF; code[i++] = 0xC6;
	code[i++] = 0xFF; code[i++] = 0xC9;
	code[i++] = 0x75; code[i++] = 0xF6;
	code[i++] = 0xC3;

	data = f + DATA_OFF;
	memcpy(payload, MARKER, mlen);
	for (i = mlen; i < DATA_RAW; i++)
		payload[i] = (unsigned char)(0x20u + ((i * 7u + 13u) % 90u));
	for (i = 0; i < DATA_RAW; i++)
		data[i] = (unsigned char)(payload[i] ^ KEY);

	*out_len = len;
	return f;
}

static void decodes(void)
{
	size_t len = 0;
	unsigned char *f = build(&len);
	struct kof_pe_info *info = calloc(1, sizeof *info);
	struct kof_obj_ctx *ctx = calloc(1, sizeof *ctx);
	struct kof_emu_unp_report rep;
	struct kof_emu *e;
	uint32_t it;
	uint64_t va, l;
	const uint8_t *bytes;
	int found = 0;

	if (!f || !info || !ctx) {
		ck(0, "out of memory building the fixture");
		goto out;
	}
	if (!kof_pe_parse(kof_buf_make(f, len), info, ctx) || !info->valid) {
		ck(0, "the hand-built PE did not parse");
		goto out;
	}
	ck(info->entry_rva == TEXT_RVA, "the entry point survived the parse");
	ck(info->sec_count == 2, "both sections were read");

	e = kof_emu_unp_run_pe(f, len, info, 0, 0, &rep);
	if (!e) {
		ck(0, rep.refused ? rep.refused : "no image could be built");
		goto out;
	}

	ck(rep.entry == BASE + TEXT_RVA, "started at the declared entry");
	ck(!rep.improvised, "nothing had to be guessed");
	ck(rep.insn > 100, "the decode loop actually ran");
	/*
	 * The stub returns, and the return address is the unmapped sentinel
	 * build_stack_pe writes. Faulting there is the CORRECT ending: it says
	 * the stub finished and did not run on into whatever followed.
	 */
	ck(rep.stop == KOF_EMU_STOP_FAULT,
	   "stopped by returning to the unmapped sentinel");
	/*
	 * And it is REPORTED as a return rather than left as a bare fault.
	 * This is the flag the harvest in objctx.c keys on: without it the
	 * most ordinary successful PE ending is filed under "ran off into
	 * nothing" and everything the stub decoded is discarded.
	 */
	ck(rep.returned, "the return was reported as a return, not a fault");

	for (it = 0; kof_emu_next_written(e, &it, &va, &bytes, &l); ) {
		uint64_t k;

		if (l < sizeof MARKER - 1)
			continue;
		for (k = 0; k + sizeof MARKER - 1 <= l; k++)
			if (!memcmp(bytes + k, MARKER, sizeof MARKER - 1)) {
				found = 1;
				break;
			}
		if (found)
			break;
	}
	ck(found, "the decoded payload came back in the written pages");
	kof_emu_free(e);

out:
	free(info);
	free(ctx);
	free(f);
	printf("pe emulation: parse, map, decode, harvest - %s\n",
	       failures ? "FAILED" : "ok");
}

/*
 * An ARM64 PE is refused by the gate rather than run, because bddisasm cannot
 * decode one and a run would spend its whole budget faulting.
 */
static void refuses_arm64(void)
{
	size_t len = 0;
	unsigned char *f = build(&len);
	struct kof_pe_info *info = calloc(1, sizeof *info);
	struct kof_obj_ctx *ctx = calloc(1, sizeof *ctx);

	if (!f || !info || !ctx) {
		ck(0, "out of memory building the fixture");
		goto out;
	}
	w16(f + 0x40 + 4, 0xAA64);        /* Machine: ARM64 */
	if (!kof_pe_parse(kof_buf_make(f, len), info, ctx) || !info->valid) {
		ck(0, "the ARM64 variant did not parse");
		goto out;
	}
	ck(kof_emu_unp_gate_pe(ctx, info, f, len) == KOF_EMU_UNP_NO,
	   "the gate refuses a machine the decoder cannot read");
out:
	free(info);
	free(ctx);
	free(f);
	printf("pe emulation: arm64 refused at the gate - %s\n",
	       failures ? "FAILED" : "ok");
}

/*
 * THE SHAPE A PACKER LEAVES, which DENSE cannot see.
 *
 * A stub in the LAST section with the entry pointing at it, and the compressed
 * original parked in a section the CPU cannot run from. That is what this
 * project's record of its own ASPack sample describes - "the zero-raw section
 * without the writable-executable one" - and it is invisible to a test that
 * measures the entropy of executable sections, because the only executable
 * section is the stub and a stub is ordinary code.
 *
 * Built so that DENSE demonstrably does NOT fire on it: the executable section
 * is 512 bytes of near-zero, and the high-entropy blob is read-only.
 */
#define AP_BLOB_RVA   0x1000u
#define AP_BLOB_OFF   0x400u
#define AP_BLOB_RAW   0x5000u
#define AP_STUB_RVA   0x6000u
#define AP_STUB_OFF   0x5400u
#define AP_STUB_RAW   0x200u

static unsigned char *build_appended(size_t *out_len)
{
	size_t len = AP_STUB_OFF + AP_STUB_RAW;
	unsigned char *f = calloc(1, len);
	unsigned char *nt, *sec;
	uint32_t lcg = 0x12345678u;
	unsigned i;

	if (!f)
		return NULL;

	f[0] = 'M';
	f[1] = 'Z';
	w32(f + 0x3c, 0x40);

	nt = f + 0x40;
	nt[0] = 'P'; nt[1] = 'E'; nt[2] = 0; nt[3] = 0;
	w16(nt + 4, 0x8664);
	w16(nt + 6, 2);
	w16(nt + 20, 0xF0);
	w16(nt + 22, 0x0022);

	{
		unsigned char *o = nt + 24;

		w16(o + 0, 0x20b);
		w32(o + 16, AP_STUB_RVA);      /* the entry is the STUB    */
		w64(o + 24, BASE);
		w32(o + 32, 0x1000);
		w32(o + 36, 0x200);
		w32(o + 56, 0x7000);
		w32(o + 60, HDR_LEN);
		w16(o + 68, 3);
		w32(o + 108, 16);
	}

	sec = nt + 24 + 0xF0;
	memcpy(sec, ".rdata\0", 8);
	w32(sec + 8,  AP_BLOB_RAW);
	w32(sec + 12, AP_BLOB_RVA);
	w32(sec + 16, AP_BLOB_RAW);
	w32(sec + 20, AP_BLOB_OFF);
	w32(sec + 36, 0x40000040u);            /* INITIALIZED | READ   */

	memcpy(sec + 40, ".stub\0\0", 8);
	w32(sec + 48, AP_STUB_RAW);
	w32(sec + 52, AP_STUB_RVA);
	w32(sec + 56, AP_STUB_RAW);
	w32(sec + 60, AP_STUB_OFF);
	w32(sec + 76, 0x60000020u);            /* CODE | EXECUTE | READ */

	/* The compressed original, as far as an entropy test can tell. */
	for (i = 0; i < AP_BLOB_RAW; i++) {
		lcg = lcg * 1664525u + 1013904223u;
		f[AP_BLOB_OFF + i] = (unsigned char)(lcg >> 24);
	}
	/* The stub: enough to be a section, not enough to be dense. */
	f[AP_STUB_OFF] = 0xC3;

	*out_len = len;
	return f;
}

static void selects_appended(void)
{
	size_t len = 0;
	unsigned char *f = build_appended(&len);
	struct kof_pe_info *info = calloc(1, sizeof *info);
	struct kof_obj_ctx *ctx = calloc(1, sizeof *ctx);

	if (!f || !info || !ctx) {
		ck(0, "out of memory building the fixture");
		goto out;
	}
	if (!kof_pe_parse(kof_buf_make(f, len), info, ctx) || !info->valid) {
		ck(0, "the packer-shaped PE did not parse");
		goto out;
	}
	ck(info->sec_count == 2, "both sections were read");
	ck(info->entry_sec == info->sec_count - 1u,
	   "the entry is in the last section");
	ck(kof_emu_unp_gate_pe(ctx, info, f, len) == KOF_EMU_UNP_WHY_APPENDED,
	   "the gate selects it, and for the appended-stub reason");
out:
	free(info);
	free(ctx);
	free(f);
	printf("pe emulation: appended stub selected by the gate - %s\n",
	       failures ? "FAILED" : "ok");
}

int main(void);
int main(void)
{
	decodes();
	refuses_arm64();
	selects_appended();
	return failures ? 1 : 0;
}
