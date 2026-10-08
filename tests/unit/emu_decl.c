/*
 * emu_decl - what a module may tell the machine BEFORE it starts: a return value
 * for a Windows API, and bytes to replace in the image. Both are data the
 * interpreter acts on; neither is a case inside it.
 *
 * The fixture is a hand-built PE32+ (see emu_pe.c for why not a sample):
 *
 *   api    calls IsDebuggerPresent / GetTickCount through the stub addresses and
 *          stores what came back in .data - so what the guest was TOLD is
 *          something the test can read, not something it must infer.
 *   xor    the decoder from emu_pe.c: XORs a page of .data with a key. A patch
 *          that turns the key into zero must leave the page encoded.
 *
 * What each case is aimed at is named in its message; a check that two
 * mechanisms could pass together proves neither.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kofmod/pe.h>
#include <kofmod/kofsig.h>
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include "../../libkofeng/extractors/unpack/emu_unpack.h"
#include "../../libkofeng/kofeng.h"

#define BASE      0x0000000140000000ull
#define HDR_LEN   0x400u
#define TEXT_RVA  0x1000u
#define DATA_RVA  0x2000u
#define TEXT_OFF  0x400u
#define DATA_OFF  0x600u
#define TEXT_RAW  0x200u
#define DATA_RAW  0x1000u
#define KEY       0x5Au

static const char MARKER[] = "KOFENG-DECLARED-PATCH-MARKER-0123456789";

static int failures;

static void ck(int ok, const char *what)
{
	printf("  %s %s\n", ok ? "ok  " : "FAIL", what);
	if (!ok)
		failures++;
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

/* A PE32+ with .text carrying `code` and .data carrying `data`. */
static unsigned char *build(const unsigned char *code, unsigned ncode,
			    const unsigned char *data, size_t *out_len)
{
	size_t len = DATA_OFF + DATA_RAW;
	unsigned char *f = calloc(1, len);
	unsigned char *nt, *sec;

	if (!f)
		return NULL;
	f[0] = 'M';
	f[1] = 'Z';
	w32(f + 0x3c, 0x40);
	nt = f + 0x40;
	memcpy(nt, "PE\0\0", 4);
	w16(nt + 4, 0x8664);
	w16(nt + 6, 2);
	w16(nt + 20, 0xF0);
	w16(nt + 22, 0x0022);
	{
		unsigned char *o = nt + 24;

		w16(o + 0, 0x20b);
		w32(o + 16, TEXT_RVA);
		w64(o + 24, BASE);
		w32(o + 32, 0x1000);
		w32(o + 36, 0x200);
		w32(o + 56, 0x3000);
		w32(o + 60, HDR_LEN);
		w16(o + 68, 3);
		w32(o + 108, 16);
	}
	sec = nt + 24 + 0xF0;
	memcpy(sec, ".text\0\0", 8);
	w32(sec + 8, TEXT_RAW);
	w32(sec + 12, TEXT_RVA);
	w32(sec + 16, TEXT_RAW);
	w32(sec + 20, TEXT_OFF);
	w32(sec + 36, 0x60000020u);
	memcpy(sec + 40, ".data\0\0", 8);
	w32(sec + 48, DATA_RAW);
	w32(sec + 52, DATA_RVA);
	w32(sec + 56, DATA_RAW);
	w32(sec + 60, DATA_OFF);
	w32(sec + 76, 0xC0000040u);
	memcpy(f + TEXT_OFF, code, ncode);
	memcpy(f + DATA_OFF, data, DATA_RAW);
	*out_len = len;
	return f;
}

/* Parse and run, with a declaration. NULL when no machine came back. */
static struct kof_emu *run(unsigned char *f, size_t len,
			   const struct kof_emu_decl *decl)
{
	static struct kof_pe_info info;
	static struct kof_obj_ctx ctx;
	struct kof_emu_unp_report rep;

	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	if (!kof_pe_parse(kof_buf_make(f, len), &info, &ctx) || !info.valid)
		return NULL;
	return kof_emu_unp_run_pe(f, len, &info, 0, 0, 0, 0, NULL, 0, decl, &rep);
}

/*
 *      mov rax, <stub of the API named first>
 *      call rax
 *      mov [rip+DATA - here], eax        ; the first answer
 *      mov rax, <stub of the second>
 *      call rax
 *      mov [rip+DATA+4 - here], eax
 *      ret
 */
static unsigned api_code(unsigned char *c, uint64_t a, uint64_t b)
{
	unsigned i = 0;

	c[i++] = 0x48; c[i++] = 0xB8; w64(c + i, a); i += 8;
	c[i++] = 0xFF; c[i++] = 0xD0;
	c[i++] = 0x89; c[i++] = 0x05;
	w32(c + i, DATA_RVA - (TEXT_RVA + i + 4)); i += 4;
	c[i++] = 0x48; c[i++] = 0xB8; w64(c + i, b); i += 8;
	c[i++] = 0xFF; c[i++] = 0xD0;
	c[i++] = 0x89; c[i++] = 0x05;
	w32(c + i, DATA_RVA + 4 - (TEXT_RVA + i + 4)); i += 4;
	c[i++] = 0xC3;
	return i;
}

static uint32_t stored(struct kof_emu *e, unsigned slot)
{
	uint32_t v = 0xdeadbeefu;

	if (!kof_emu_read(e, BASE + DATA_RVA + 4u * slot, &v, 4u))
		return 0xdeadbeefu;
	return v;
}

static void api(void)
{
	static unsigned char data[DATA_RAW];
	unsigned char code[64];
	unsigned char *f;
	size_t len = 0;
	struct kof_emu *e;
	struct kof_emu_decl d;
	uint64_t dbg, tick;
	unsigned n;
	uint32_t base_dbg, base_tick;

	printf("api shim:\n");
	/* The stub addresses of this environment: a throwaway run to learn them.
	 * They are properties of the module images, not of one run. */
	{
		unsigned char nop[1] = { 0xC3 };

		f = build(nop, 1, data, &len);
		e = f ? run(f, len, NULL) : NULL;
		if (!e) {
			ck(0, "a machine to learn the stub addresses from");
			free(f);
			return;
		}
		dbg = kof_emu_win_addr_of(e, "IsDebuggerPresent");
		tick = kof_emu_win_addr_of(e, "GetTickCount");
		kof_emu_free(e);
		free(f);
	}
	ck(dbg && tick, "both stubs exist in this environment");

	n = api_code(code, dbg, tick);

	f = build(code, n, data, &len);
	e = f ? run(f, len, NULL) : NULL;
	ck(e != NULL, "the control run produced a machine");
	if (!e) {
		free(f);
		return;
	}
	base_dbg = stored(e, 0);
	base_tick = stored(e, 1);
	ck(base_dbg == 0, "control: IsDebuggerPresent says no debugger");
	kof_emu_free(e);

	memset(&d, 0, sizeof d);
	strcpy(d.shim[0].name, "IsDebuggerPresent");
	d.shim[0].ret = 1;
	d.n_shim = 1;
	e = run(f, len, &d);
	ck(e && stored(e, 0) == 1,
	   "a declared value is what the guest is told");
	ck(e && stored(e, 1) == base_tick,
	   "an API nobody declared still answers as it did (unrelated call unaffected)");
	if (e)
		kof_emu_free(e);

	/* Aimed at the table: a second declaration for the SAME name replaces the
	 * first, so the order a module declares in cannot leave two answers. */
	memset(&d, 0, sizeof d);
	strcpy(d.shim[0].name, "GetTickCount");
	d.shim[0].ret = 0x12345u;
	strcpy(d.shim[1].name, "GetTickCount");
	d.shim[1].ret = 0x777u;
	d.n_shim = 2;
	e = run(f, len, &d);
	ck(e && stored(e, 1) == 0x777u && stored(e, 0) == base_dbg,
	   "the later declaration of one name wins, and the other API is untouched");
	if (e)
		kof_emu_free(e);

	/* Aimed at the name check: a name this environment has no handler for does
	 * nothing and is reported as not kept. */
	e = run(f, len, NULL);
	ck(e && kof_emu_shim_api(e, "NoSuchApiAnywhere", 1) == 0,
	   "a name the table lacks is refused, not silently kept");
	ck(e && kof_emu_shim_api(e, NULL, 1) == 0, "a NULL name is refused");
	if (e) {
		unsigned i;
		int all = 1;

		/* And the declaration table is a bound on the DECLARATION. Fill it
		 * with distinct real names; the first KOF_EMU_SHIM_MAX are kept and
		 * the next is refused, nothing grows. */
		for (i = 0; i < kof_emu_win_api_count() && i < KOF_EMU_SHIM_MAX; i++)
			if (!kof_emu_shim_api(e, kof_emu_win_api_name(i), 1))
				all = 0;
		ck(all, "a table's worth of distinct names is kept");
		if (kof_emu_win_api_count() > KOF_EMU_SHIM_MAX)
			ck(kof_emu_shim_api(e, kof_emu_win_api_name(KOF_EMU_SHIM_MAX), 1) == 0,
			   "one more than the table holds is refused");
		kof_emu_free(e);
	}
	free(f);
}

/* The decoder from emu_pe.c. Its key byte is the patch target. */
static unsigned xor_code(unsigned char *c)
{
	unsigned i = 0;

	c[i++] = 0x48; c[i++] = 0xBE; w64(c + i, BASE + DATA_RVA); i += 8;
	c[i++] = 0xB9; w32(c + i, DATA_RAW); i += 4;
	c[i++] = 0x80; c[i++] = 0x36; c[i++] = KEY;
	c[i++] = 0x48; c[i++] = 0xFF; c[i++] = 0xC6;
	c[i++] = 0xFF; c[i++] = 0xC9;
	c[i++] = 0x75; c[i++] = 0xF6;
	c[i++] = 0xC3;
	return i;
}

static int marker_written(struct kof_emu *e)
{
	uint32_t it = 0;
	uint64_t va, l, k;
	const uint8_t *b;

	while (kof_emu_next_written(e, &it, &va, &b, &l))
		for (k = 0; l >= sizeof MARKER - 1 && k + sizeof MARKER - 1 <= l; k++)
			if (!memcmp(b + k, MARKER, sizeof MARKER - 1))
				return 1;
	return 0;
}

static void patch(void)
{
	unsigned char code[64], data[DATA_RAW], payload[DATA_RAW], *f, *orig;
	unsigned n, i, mlen = (unsigned)sizeof MARKER;
	size_t len = 0;
	struct kof_emu *e;
	struct kof_emu_decl d;
	static const unsigned char find[3] = { 0x80, 0x36, KEY };
	static const unsigned char zero[3] = { 0x80, 0x36, 0x00 };
	static const unsigned char none[3] = { 0xDE, 0xAD, 0xC0 };

	printf("image patch:\n");
	memcpy(payload, MARKER, mlen);
	for (i = mlen; i < DATA_RAW; i++)
		payload[i] = (unsigned char)(0x20u + ((i * 7u + 13u) % 90u));
	for (i = 0; i < DATA_RAW; i++)
		data[i] = (unsigned char)(payload[i] ^ KEY);
	n = xor_code(code);
	f = build(code, n, data, &len);
	orig = f ? malloc(len) : NULL;
	if (!f || !orig) {
		ck(0, "fixture");
		free(f);
		free(orig);
		return;
	}
	memcpy(orig, f, len);

	e = run(f, len, NULL);
	ck(e && marker_written(e), "control: the stub decodes the payload");
	if (e)
		kof_emu_free(e);

	memset(&d, 0, sizeof d);
	memcpy(d.patch[0].find, find, 3);
	memcpy(d.patch[0].rep, zero, 3);
	d.patch[0].n = 3;
	d.n_patch = 1;
	e = run(f, len, &d);
	ck(e != NULL, "a patched image still runs");
	ck(e && !marker_written(e),
	   "a patched key byte leaves the payload encoded (the patch was applied)");
	if (e)
		kof_emu_free(e);
	ck(!memcmp(f, orig, len),
	   "the caller's file is untouched - the patch lives in the mapped copy");

	/* Aimed at the matcher: a pattern that matches nothing changes nothing. */
	memset(&d, 0, sizeof d);
	memcpy(d.patch[0].find, none, 3);
	memcpy(d.patch[0].rep, zero, 3);
	d.patch[0].n = 3;
	d.n_patch = 1;
	e = run(f, len, &d);
	ck(e && marker_written(e), "a pattern that does not occur changes nothing");
	if (e)
		kof_emu_free(e);

	/* Aimed at the length guard: an entry whose n is out of range is ignored,
	 * never read past its arrays. */
	memset(&d, 0, sizeof d);
	memcpy(d.patch[0].find, find, 3);
	memcpy(d.patch[0].rep, zero, 3);
	d.patch[0].n = KOF_EMU_PATCH_LEN + 1u;
	d.n_patch = 1;
	e = run(f, len, &d);
	ck(e && marker_written(e), "an out-of-range length is ignored");
	if (e)
		kof_emu_free(e);

	/* Aimed at where it looks: the same three bytes ONLY inside the headers
	 * are not code, so declaring them patches nothing. */
	{
		unsigned char hdr_find[3] = { 'P', 'E', 0 };
		unsigned char hdr_rep[3] = { 'X', 'X', 'X' };

		memset(&d, 0, sizeof d);
		memcpy(d.patch[0].find, hdr_find, 3);
		memcpy(d.patch[0].rep, hdr_rep, 3);
		d.patch[0].n = 3;
		d.n_patch = 1;
		e = run(f, len, &d);
		ck(e && marker_written(e),
		   "bytes found only outside every section are not patched");
		if (e)
			kof_emu_free(e);
	}
	free(f);
	free(orig);
}

int main(void);
int main(void)
{
	api();
	patch();
	printf("emu_decl: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
