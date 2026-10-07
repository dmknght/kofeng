/*
 * diag_pe - the calls a PE makes through its import table become nodes.
 *
 * WHY A TEST AND NOT A CORPUS RUN. A corpus says how many nodes appeared. These
 * cases say which instruction a node sits on and which it must not:
 *
 *   DATA IN THE CODE   a decoder that treats "could not read this byte" as "the
 *                      section is finished" stopped at the first jump table of
 *                      a 180 KB .text - 98 nodes, all in the first fifth of the
 *                      file. The call here sits AFTER bytes that do not decode.
 *   THE x86 STUB       a 32-bit toolchain calls `jmp [slot]`, not the slot. The
 *                      node belongs on the CALL to the stub, once per caller.
 *   NOT AN IMPORT      an indirect call through memory that is no import slot
 *                      says nothing about what it calls.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/detectors/pathogen/kofdiag.h"
#include "../../libkofeng/analyzers/parsers/binaries/disasm/nucleo.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static void put64(uint8_t *b, unsigned at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void put32(uint8_t *b, unsigned at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void put16(uint8_t *b, unsigned at, uint16_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}
static unsigned char view[1u << 21];



#define TEXT_RVA   0x1000u
#define IDATA_OFF  0x100u       /* inside the one section, to keep the file small */

/* The one section holds code at the front and an import directory behind it.
 * kernel32.dll!VirtualAlloc, one thunk, FirstThunk at +0x160 and the name at
 * +0x190. `wide` selects PE32+ (8-byte thunks) or PE32 (4-byte). */
static uint64_t pe_with_import(uint8_t *b, uint64_t cap, int wide,
			       const uint8_t *code, uint64_t n, int with_import)
{
	const unsigned hdr = 0x400, fa = 0x200, o = 0x80 + 24;
	const unsigned sec = o + 0xf0;
	const unsigned id = hdr + IDATA_OFF;
	const unsigned rva_id = TEXT_RVA + IDATA_OFF;
	const unsigned w = wide ? 8u : 4u;

	memset(b, 0, (size_t)cap);
	b[0] = 'M'; b[1] = 'Z';
	put32(b, 0x3c, 0x80);
	memcpy(b + 0x80, "PE\0\0", 4);
	put16(b, 0x84, wide ? 0x8664u : 0x014cu);
	put16(b, 0x86, 1);
	put16(b, 0x94, 0xf0);
	put16(b, 0x96, 0x22);
	put16(b, o, wide ? 0x20bu : 0x10bu);
	b[o + 2] = 14;
	put32(b, o + 4, (uint32_t)n);
	put32(b, o + 16, TEXT_RVA);
	put32(b, o + 20, TEXT_RVA);
	if (wide) {
		put64(b, o + 24, 0x140000000ull);
		put32(b, o + 32, 0x1000);
		put32(b, o + 36, fa);
		put16(b, o + 40, 6);
		put16(b, o + 48, 6);
		put32(b, o + 56, 0x2000);
		put32(b, o + 60, hdr);
		put16(b, o + 68, 3);
		put32(b, o + 108, 16);
		if (with_import) {
			put32(b, o + 112 + 8, rva_id);
			put32(b, o + 112 + 12, 40);
		}
	} else {
		put32(b, o + 24, 0x1000);
		put32(b, o + 28, 0x400000);
		put32(b, o + 32, 0x1000);
		put32(b, o + 36, fa);
		put16(b, o + 40, 6);
		put16(b, o + 48, 6);
		put32(b, o + 56, 0x2000);
		put32(b, o + 60, hdr);
		put16(b, o + 68, 3);
		put32(b, o + 92, 16);
		if (with_import) {
			put32(b, o + 96 + 8, rva_id);
			put32(b, o + 96 + 12, 40);
		}
	}
	memcpy(b + sec, ".text\0\0\0", 8);
	put32(b, sec + 8, 0x1000);
	put32(b, sec + 12, TEXT_RVA);
	put32(b, sec + 16, fa);
	put32(b, sec + 20, hdr);
	put32(b, sec + 36, 0xe0000020u);        /* CODE|EXEC|READ|WRITE */
	memcpy(b + hdr, code, (size_t)n);
	if (with_import) {
		/* descriptor: OriginalFirstThunk, 0, 0, Name, FirstThunk */
		put32(b, id + 0, rva_id + 0x40);
		put32(b, id + 12, rva_id + 0x80);
		put32(b, id + 16, rva_id + 0x60);
		/* both thunk tables hold the RVA of the hint/name entry */
		put32(b, id + 0x40, rva_id + 0x90);
		put32(b, id + 0x60, rva_id + 0x90);
		(void)w;
		memcpy(b + id + 0x80, "kernel32.dll", 13);
		memcpy(b + id + 0x92, "VirtualAlloc", 13);   /* after the 2-byte hint */
	}
	return hdr + fa;
}

static uint32_t count(struct kof_diag_scan *s)
{
	return s ? kof_diag_scan_count(s) : 0;
}

static struct kof_diag_scan *scan(const uint8_t *b, uint64_t n,
				  struct kof_obj_ctx *ctx, const char *what)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf;

	buf.p = b;
	buf.n = n;
	memset(ctx, 0, sizeof *ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) &&
		    pl[i].parse && pl[i].parse(buf, view, ctx))
			return kof_diag_scan_with(ctx, b, n, KOF_DIAG_RUN_SYMBOL);
	printf("  FAIL %s: the engine did not parse it\n", what);
	fails++;
	return NULL;
}

int main(void)
{
	static uint8_t b[0x1000], code[0x100];
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *s;
	const uint16_t want = kof_flow_cap_of_name("VirtualAlloc");
	uint32_t i, hits;
	uint64_t n;

	CK(want != KOF_NUCLEO_NONE);    /* the vocabulary has a word for it */

	/*
	 * 1. x64, AFTER BYTES THAT DO NOT DECODE. 0x06 (push es) is invalid in 64-bit
	 *    mode, so the decoder answers "nothing" for each - MEASURED, 0xd6 is
	 *    not and an earlier version of this test used it and could not fail; the call behind them must
	 *    still be found. The slot is image_base + FirstThunk (0x1000+0x160).
	 */
	memset(code, 0x90, sizeof code);
	code[0] = 0x06; code[1] = 0x06; code[2] = 0x06; code[3] = 0x06;
	code[4] = 0xff; code[5] = 0x15;                       /* call [rip+disp] */
	put32(code, 6, (uint32_t)((TEXT_RVA + IDATA_OFF + 0x60) - (TEXT_RVA + 4u + 6u)));
	code[10] = 0xc3;
	n = pe_with_import(b, sizeof b, 1, code, 0x100, 1);
	s = scan(b, n, &ctx, "x64 import call");
	hits = 0;
	for (i = 0; s && i < count(s); i++) {
		const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

		if (h->cap == want && h->at == 0x400u + 4u) {
			hits++;
			/* the node says WHICH import: the name is where the table put it */
			CK(h->bits & KOF_DIAG_H_SYMREF);
			CK(h->symref + 12u <= n &&
			   !memcmp(b + h->symref, "VirtualAlloc", 13));
		}
	}
	CK(hits == 1);
	kof_diag_scan_free(s);

	/*
	 * 2. x86 THROUGH A STUB: two callers, one `jmp [slot]`. A node on each
	 *    CALL, none on the stub itself.
	 */
	memset(code, 0x90, sizeof code);
	code[0] = 0xe8; put32(code, 1, 0x20u - 5u);           /* call stub   */
	code[5] = 0xe8; put32(code, 6, 0x20u - 10u);          /* call stub   */
	code[10] = 0xc3;
	code[0x20] = 0xff; code[0x21] = 0x25;                 /* jmp [abs32] */
	put32(code, 0x22, 0x400000u + TEXT_RVA + IDATA_OFF + 0x60u);
	n = pe_with_import(b, sizeof b, 0, code, 0x100, 1);
	s = scan(b, n, &ctx, "x86 stub");
	{
		int at0 = 0, at5 = 0, on_stub = 0;

		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			if (h->cap != want)
				continue;
			at0 += h->at == 0x400u;
			at5 += h->at == 0x405u;
			on_stub += h->at == 0x420u;
		}
		CK(at0 == 1);
		CK(at5 == 1);
		CK(on_stub == 0);
	}
	kof_diag_scan_free(s);

	/*
	 * 3. NOT AN IMPORT: an indirect call through a fixed address that is not
	 *    the import slot, and one through a register-indexed table.
	 */
	memset(code, 0x90, sizeof code);
	code[0] = 0xff; code[1] = 0x15;                       /* call [rip+disp] elsewhere */
	put32(code, 2, 0x80u);
	code[6] = 0xff; code[7] = 0x14; code[8] = 0x85;       /* call [rax*4+disp32] */
	put32(code, 9, TEXT_RVA + IDATA_OFF + 0x60u);
	code[13] = 0xc3;
	n = pe_with_import(b, sizeof b, 1, code, 0x100, 1);
	s = scan(b, n, &ctx, "not an import");
	for (i = 0; s && i < count(s); i++)
		CK(kof_diag_scan_at(s, i)->cap != want);
	kof_diag_scan_free(s);

	/* 4. NO IMPORT DIRECTORY: nothing to match, nothing invented. */
	n = pe_with_import(b, sizeof b, 1, code, 0x100, 0);
	s = scan(b, n, &ctx, "no imports");
	CK(count(s) == 0);
	kof_diag_scan_free(s);

	printf("diag pe: import calls, data in the code, the x86 stub, a call that is not an import%s\n",
	       fails ? " - FAILED" : " - ok");
	return fails != 0;
}
