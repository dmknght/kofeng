/*
 * emu_oep - when has a PE stub handed over to the program it unpacked?
 *
 * The question is answered from what the run DID, with no packer named: control
 * moves, with the stack as the stub found it, from code the file supplied into
 * code the guest wrote, and not into the stub's own section, and then nothing
 * else is handed over for a quiet window - a protector's next stage would be.
 * Hand-built PE32+ files, one positive and two that look like it:
 *
 *   hands_over     a stub in the last section decodes a payload into the first
 *                  and jumps BACK to it, which is how a UPX stub ends. The
 *                  payload spins forever, so a run that does not recognise the
 *                  transfer goes on until a ceiling instead of stopping at it.
 *   inside_stub    the same decoder writing into the stub's OWN section and
 *                  jumping to it: a loader moving within itself.
 *   with_call      the transfer is a CALL, so the stack is not as the stub
 *                  found it: it is going to return.
 *
 * MUTATION CHECK, measured: with the candidate arm in kofemu.c disabled,
 * hands_over fails (the run ends at the budget); with the stub-range guard
 * removed, inside_stub fails.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kofmod/pe.h>
#include <kofmod/kofsig.h>
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include "../../libkofeng/extractors/unpack/emu_unpack.h"
#include "../../libkofeng/kofeng.h"

#define BASE     0x0000000140000000ull
#define KEY      0x5Au
#define BUDGET   4000000ull

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
	w16(p, (unsigned)(v & 0xffffu));
	w16(p + 2, (unsigned)(v >> 16));
}

static void w64(unsigned char *p, unsigned long long v)
{
	w32(p, (unsigned long)(v & 0xffffffffu));
	w32(p + 4, (unsigned long)(v >> 32));
}

/* The payload: a spin, then padding, long enough to be an image and not a
 * stage - the candidate test asks for sixteen pages of the guest's own
 * writing around the target. */
static const unsigned char SPIN[] = { 0xEB, 0xFE };
#define PAY_LEN 0x10010u

/*
 * Layout, both sections RWX so that no permission decides the outcome:
 *   .orig  rva 0x01000, 0x12000 bytes, raw bytes present (zero)
 *   .stub  rva 0x13000, 0x22000 bytes, all raw: a scratch area of 17 pages,
 *          the code at +0x11100 and the encoded payload at +0x11180.
 *          The code is on a page of its own so that writing the scratch area
 *          does not turn the page the jump leaves from into a written page.
 * `dst` is where the payload is decoded to, `how` how control gets there.
 */
enum how { JMP_REG, CALL_REG };

#define ORIG_RVA  0x01000ul
#define STUB_RVA  0x13000ul
#define ORIG_RAW  0x0E000u
#define STUB_RAW  0x21200u
#define HDR       0x400u

static unsigned char *build(size_t *out_len, unsigned long dst, enum how how,
			    unsigned plen)
{
	size_t len = HDR + ORIG_RAW + STUB_RAW;
	unsigned char *f = calloc(1, len);
	unsigned char *nt, *sec, *c;
	unsigned i = 0;

	if (!f)
		return NULL;
	f[0] = 'M'; f[1] = 'Z';
	w32(f + 0x3c, 0x40);
	nt = f + 0x40;
	nt[0] = 'P'; nt[1] = 'E';
	w16(nt + 4, 0x8664);
	w16(nt + 6, 2);
	w16(nt + 20, 0xF0);
	w16(nt + 22, 0x0022);
	{
		unsigned char *o = nt + 24;

		w16(o + 0, 0x20b);
		w32(o + 16, STUB_RVA + 0x11100u);   /* entry: in .stub */
		w64(o + 24, BASE);
		w32(o + 32, 0x1000);
		w32(o + 36, 0x200);
		w32(o + 56, STUB_RVA + 0x22000u);
		w32(o + 60, HDR);
		w16(o + 68, 3);
		w32(o + 108, 16);
	}
	sec = nt + 24 + 0xF0;
	memcpy(sec, ".orig\0\0", 8);
	w32(sec + 8, 0x12000); w32(sec + 12, ORIG_RVA);
	w32(sec + 16, ORIG_RAW); w32(sec + 20, HDR);
	w32(sec + 36, 0xE0000020u);
	memcpy(sec + 40, ".stub\0\0", 8);
	w32(sec + 48, 0x22000); w32(sec + 52, STUB_RVA);
	w32(sec + 56, STUB_RAW); w32(sec + 60, HDR + ORIG_RAW);
	w32(sec + 76, 0xE0000020u);

	c = f + HDR + ORIG_RAW + 0x11100u;
	c[i++] = 0x48; c[i++] = 0xBE;                 /* mov rsi, src     */
	w64(c + i, BASE + STUB_RVA + 0x11180u); i += 8;
	c[i++] = 0x48; c[i++] = 0xBF;                 /* mov rdi, dst     */
	w64(c + i, BASE + dst); i += 8;
	c[i++] = 0xB9; w32(c + i, plen); i += 4;   /* mov ecx, len     */
	c[i++] = 0x8A; c[i++] = 0x06;                 /* L: mov al,[rsi]  */
	c[i++] = 0x34; c[i++] = KEY;                  /*    xor al, KEY   */
	c[i++] = 0x88; c[i++] = 0x07;                 /*    mov [rdi], al */
	c[i++] = 0x48; c[i++] = 0xFF; c[i++] = 0xC6;  /*    inc rsi       */
	c[i++] = 0x48; c[i++] = 0xFF; c[i++] = 0xC7;  /*    inc rdi       */
	c[i++] = 0xFF; c[i++] = 0xC9;                 /*    dec ecx       */
	c[i++] = 0x75; c[i++] = 0xF0;                 /*    jnz L         */
	c[i++] = 0x48; c[i++] = 0xB8;                 /* mov rax, dst     */
	w64(c + i, BASE + dst); i += 8;
	c[i++] = 0xFF; c[i++] = how == JMP_REG ? 0xE0 : 0xD0;
	c[i++] = 0xC3;
	{
		unsigned char *p = f + HDR + ORIG_RAW + 0x11180u;
		unsigned k;

		for (k = 0; k < plen; k++)
			p[k] = (unsigned char)(((k < sizeof SPIN) ? SPIN[k] : 0x90u) ^ KEY);
	}
	*out_len = len;
	return f;
}

static enum kof_emu_stop run(unsigned long dst, enum how how, unsigned plen,
			     uint64_t *insn, char *detail, size_t dn)
{
	size_t len = 0;
	unsigned char *f = build(&len, dst, how, plen);
	struct kof_pe_info *info = calloc(1, sizeof *info);
	struct kof_obj_ctx *ctx = calloc(1, sizeof *ctx);
	struct kof_emu_unp_report rep;
	struct kof_emu *e;
	enum kof_emu_stop st = KOF_EMU_STOP_DECODE;

	detail[0] = 0;
	if (!f || !info || !ctx || !kof_pe_parse(kof_buf_make(f, len), info, ctx) ||
	    !info->valid) {
		ck(0, "the fixture did not build or parse");
		goto out;
	}
	e = kof_emu_unp_run_pe(f, len, info, BUDGET, 0, 0, 0, NULL, 0, NULL,
			       &rep);
	if (!e) {
		ck(0, rep.refused ? rep.refused : "no image");
		goto out;
	}
	st = rep.stop;
	*insn = rep.insn;
	if (rep.detail)
		snprintf(detail, dn, "%s", rep.detail);
	kof_emu_free(e);
out:
	free(info);
	free(ctx);
	free(f);
	return st;
}


/*
 * A NAME THE TABLE LACKS IS ANSWERED, A KNOWN ONE IS NOT DISTURBED. The miss
 * thunk lies in the null page (so the call0 policy owns it), a modelled name
 * keeps its real stub, and anything that is not an identifier is still 0.
 */
static void resolves(void)
{
	size_t len = 0;
	unsigned char *f = build(&len, ORIG_RVA, JMP_REG, PAY_LEN);
	struct kof_pe_info *info = calloc(1, sizeof *info);
	struct kof_obj_ctx *ctx = calloc(1, sizeof *ctx);
	struct kof_emu_unp_report rep;
	struct kof_emu *e = NULL;

	if (f && info && ctx && kof_pe_parse(kof_buf_make(f, len), info, ctx) &&
	    info->valid)
		e = kof_emu_unp_run_pe(f, len, info, 1000, 0, 0, 0, NULL, 0, NULL,
				       &rep);
	if (!e) {
		ck(0, "no machine to resolve against");
	} else {
		uint64_t k = kof_emu_win_addr_of(e, "GetProcAddress");
		uint64_t a = kof_emu_win_resolve(e, "DeleteFileW");
		uint64_t b = kof_emu_win_resolve(e, "DeleteFileW");

		ck(k && kof_emu_win_resolve(e, "GetProcAddress") == k,
		   "a modelled name keeps its real stub");
		ck(a > 0 && a < 0x1000, "a plausible name the table lacks gets a null-page thunk");
		ck(b != a, "and two answers are two addresses");
		ck(kof_emu_win_resolve(e, "no way!") == 0, "a non-identifier is still refused");
		ck(kof_emu_win_resolve(e, "ab") == 0, "and so is a name too short to be one");
		kof_emu_free(e);
	}
	free(info);
	free(ctx);
	free(f);
	printf("pe resolve: unknown export gets a thunk - %s\n",
	       failures ? "FAILED" : "ok");
}

int main(void);
int main(void)
{
	uint64_t insn = 0;
	char d[96];
	enum kof_emu_stop st;

	/* A stub in the last section writes the first and jumps back to it. */
	st = run(ORIG_RVA, JMP_REG, PAY_LEN, &insn, d, sizeof d);
	ck(st == KOF_EMU_STOP_HANDOFF, "a jump from the stub into written code is the handover");
	/* The transfer is only a candidate: the run stops when nothing
	 * challenges it for the quiet window, which is well under the budget. */
	ck(insn > 1000000 && insn < BUDGET, "and it stops after the quiet window, not at the budget");
	ck(!strncmp(d, "handover", 8), "and says it is a handover");

	/* The same decoder, into its own section. */
	st = run(STUB_RVA, JMP_REG, PAY_LEN, &insn, d, sizeof d);
	ck(st != KOF_EMU_STOP_HANDOFF, "a loader moving inside its own section is not a handover");

	/* Only a few pages: a stage of a loader, not the program. */
	st = run(ORIG_RVA, JMP_REG, 0x3000, &insn, d, sizeof d);
	ck(st != KOF_EMU_STOP_HANDOFF, "a transfer into a few pages is a stage, not the program");

	/* A call: the stack is not as the stub found it. */
	st = run(ORIG_RVA, CALL_REG, PAY_LEN, &insn, d, sizeof d);
	ck(st != KOF_EMU_STOP_HANDOFF, "a call into written code is not a handover");

	resolves();

	printf("pe oep: transfer from file code into written code - %s\n",
	       failures ? "FAILED" : "ok");
	return failures ? 1 : 0;
}
