/*
 * emu_imptab.c - the emulator fills a PE's IAT from the object's import table
 * and does not walk the directory itself.
 *
 * Three ways of calling kgenome_emu_unp_run_pe have to leave the same thunks in the
 * guest: with no table (the run builds one with kgenome_pe_imptab_build), with the
 * table the caller built from this very buffer (the scanner's shape - the
 * directory is walked once per object), and with a table built from OTHER bytes
 * (whose offsets would index the wrong buffer, so it must not be read). A named
 * import becomes the stub's address; an import by ordinal is left as the file
 * wrote it, because this environment has no names for those.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kofmod/pe.h>
#include <kofmod/kofsig.h>
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include <phenotype/emu_unpack.h>
#include "../../libkofeng/kofeng.h"

#define BASE      0x0000000140000000ull
#define TEXT_RVA  0x1000u
#define DATA_RVA  0x2000u
#define TEXT_OFF  0x400u
#define DATA_OFF  0x600u
#define DATA_RAW  0x1000u
/* inside .data */
#define IDESC     0x000u
#define ILT       0x100u
#define IAT       0x200u
#define HINTNAME  0x300u
#define DLLNAME   0x340u
#define ORDINAL   0x8000000000000000ull

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

static unsigned char *build(size_t *out_len)
{
	size_t len = DATA_OFF + DATA_RAW;
	unsigned char *f = calloc(1, len);
	unsigned char *nt, *sec, *d;

	if (!f)
		return NULL;
	f[0] = 'M';
	f[1] = 'Z';
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
		w32(o + 16, TEXT_RVA);
		w64(o + 24, BASE);
		w32(o + 32, 0x1000);
		w32(o + 36, 0x200);
		w32(o + 56, 0x3000);
		w32(o + 60, 0x400);
		w16(o + 68, 3);
		w32(o + 108, 16);
		w32(o + 112 + 8 * 1, DATA_RVA + IDESC);   /* import directory */
		w32(o + 112 + 8 * 1 + 4, 40);
	}
	sec = nt + 24 + 0xF0;
	memcpy(sec, ".text\0\0", 8);
	w32(sec + 8, 0x200); w32(sec + 12, TEXT_RVA);
	w32(sec + 16, 0x200); w32(sec + 20, TEXT_OFF);
	w32(sec + 36, 0x60000020u);
	memcpy(sec + 40, ".data\0\0", 8);
	w32(sec + 48, DATA_RAW); w32(sec + 52, DATA_RVA);
	w32(sec + 56, DATA_RAW); w32(sec + 60, DATA_OFF);
	w32(sec + 76, 0xC0000040u);

	f[TEXT_OFF] = 0xC3;                              /* ret */

	d = f + DATA_OFF;
	w32(d + IDESC + 0,  DATA_RVA + ILT);             /* OriginalFirstThunk */
	w32(d + IDESC + 12, DATA_RVA + DLLNAME);         /* Name               */
	w32(d + IDESC + 16, DATA_RVA + IAT);             /* FirstThunk         */
	w64(d + ILT + 0, DATA_RVA + HINTNAME);           /* by name            */
	w64(d + ILT + 8, ORDINAL | 7u);                  /* by ordinal         */
	w64(d + IAT + 0, DATA_RVA + HINTNAME);
	w64(d + IAT + 8, ORDINAL | 7u);
	memcpy(d + HINTNAME + 2, "VirtualAlloc", 13);
	memcpy(d + DLLNAME, "kernel32.dll", 13);
	*out_len = len;
	return f;
}

static int iat(struct kgenome_emu *e, uint64_t *named, uint64_t *ord)
{
	return kgenome_emu_read(e, BASE + DATA_RVA + IAT, named, 8) &&
	       kgenome_emu_read(e, BASE + DATA_RVA + IAT + 8, ord, 8);
}

static void run(const char *what, unsigned char *f, size_t len,
		struct kgenome_pe_info *info, const struct kgenome_pe_imptab *tab,
		uint64_t *named, uint64_t *ord)
{
	struct kgenome_emu_unp_report rep;
	struct kgenome_budget bud = { .max_insn = 1000 };
	struct kgenome_emu *e = kgenome_emu_unp_run_pe(f, len, info, tab, &bud, 0, 0,
					       0, NULL, 0, NULL, &rep);
	uint64_t stub;

	*named = *ord = 0;
	ck(e != NULL, what);
	if (!e)
		return;
	ck(iat(e, named, ord), "the thunks are readable");
	stub = kgenome_emu_win_addr_of(e, "VirtualAlloc");
	ck(stub != 0, "the environment has VirtualAlloc");
	ck(*named == stub, "a named import is the stub's address");
	ck(*ord == (ORDINAL | 7u), "an import by ordinal is left as written");
	kgenome_emu_free(e);
}

int main(void)
{
	size_t len = 0;
	unsigned char *f = build(&len), *g;
	struct kgenome_pe_info *info = calloc(1, sizeof *info);
	struct kof_obj_ctx *ctx = calloc(1, sizeof *ctx);
	struct kgenome_pe_imptab own, other;
	uint64_t a0, a1, b0, b1, c0, c1;

	memset(&own, 0, sizeof own);
	memset(&other, 0, sizeof other);
	if (!f || !info || !ctx || !(g = malloc(len))) {
		ck(0, "out of memory building the fixture");
		goto out;
	}
	memcpy(g, f, len);
	/* the other bytes name their import somewhere else, so a table made from
	 * them points at offsets that are empty in `f` */
	w64(g + DATA_OFF + ILT, DATA_RVA + HINTNAME + 0x20u);
	memcpy(g + DATA_OFF + HINTNAME + 0x22u, "VirtualFree", 12);
	if (!kof_pe_parse(kof_buf_make(f, len), info, ctx) || !info->valid) {
		ck(0, "the hand-built PE did not parse");
		goto out;
	}
	kgenome_pe_imptab_build(kof_buf_make(f, len), info, &own);
	kgenome_pe_imptab_build(kof_buf_make(g, len), info, &other);
	ck(own.n == 2, "the table holds both imports");
	ck(kgenome_pe_imptab_is_of(&own, kof_buf_make(f, len)), "the table knows its buffer");
	ck(!kgenome_pe_imptab_is_of(&other, kof_buf_make(f, len)), "and not another");

	run("run with no table", f, len, info, NULL, &a0, &a1);
	run("run with the object's table", f, len, info, &own, &b0, &b1);
	run("run with a table of other bytes", f, len, info, &other, &c0, &c1);
	ck(a0 == b0 && a1 == b1, "no table and a handed table fill the same thunks");
	ck(a0 == c0 && a1 == c1, "a table of other bytes is not read");
out:
	kgenome_pe_imptab_free(&own);
	kgenome_pe_imptab_free(&other);
	free(info);
	free(ctx);
	free(f);
	free(g);
	printf("emu import table: handed, built and refused tables - %s\n",
	       failures ? "FAILED" : "ok");
	return failures ? 1 : 0;
}
