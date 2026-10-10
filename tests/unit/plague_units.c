/*
 * plague_units - how an object is cut into the units a block is made from, and
 * where a PE's functions come from.
 *
 * The scanner and the authoring tool both call kof_plague_units, so what this
 * pins is the cut itself: a function region yields functions - grouped when
 * small, dropped when stubs or the library's, none when the symbols are absent -
 * and any other region tiles exactly, split at a library boundary with a side
 * on every piece.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detectors/overlord/plague/kofplague.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"
#include "../../libkofeng/kofcore/kofmod/pe.h"

static int failures;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

struct got {
	uint64_t off[64], len[64];
	uint32_t side[64];
	uint32_t n;
};

static int take(void *user, uint64_t off, uint64_t len, uint32_t side,
		const struct kof_func *first)
{
	struct got *g = user;

	(void)first;
	if (g->n < 64u) {
		g->off[g->n] = off; g->len[g->n] = len; g->side[g->n] = side;
		g->n++;
	}
	return 0;
}

static void functions(void)
{
	static uint8_t obj[8192];
	struct kof_func v[6] = {
		{ 100, 300, 0, 0 },   /* a function */
		{ 500, 100, 0, 0 },   /* small, next to the next one ... */
		{ 610, 100, 0, 0 },   /* ... so the two are one unit of 500..710 */
		{ 2000, 40, 0, 0 },   /* a stub: under the floor alone */
		{ 3000, 200, 0, 0 },  /* the library's */
		{ 5000, 100, 0, 0 },  /* outside the region */
	};
	struct kof_func_set fs;
	struct kof_range ext = { 0, 4000 };
	struct kof_true_all lib;
	struct got g;

	memset(&fs, 0, sizeof fs);
	fs.v = v; fs.n = 6;
	memset(&lib, 0, sizeof lib);
	lib.span[0].off = 3100; lib.span[0].len = 50; lib.n = 1;

	memset(&g, 0, sizeof g);
	kof_plague_units(obj, sizeof obj, KOF_FMT_ELF, KOF_SCAN_ELF_CODE, &ext, 1,
			 &fs, &lib, take, &g);
	check(g.n == 2u, "the units of a function region are the functions that count");
	check(g.n >= 1u && g.off[0] == 100u && g.len[0] == 300u,
	      "a function is a unit of its own extent");
	check(g.n >= 2u && g.off[1] == 500u && g.len[1] == 210u,
	      "small functions that sit together are one unit");
	check(g.side[0] == KOF_PLAGUE_SIDE_USER, "a function is on the author's side");

	memset(&g, 0, sizeof g);
	kof_plague_units(obj, sizeof obj, KOF_FMT_ELF, KOF_SCAN_ELF_CODE, &ext, 1,
			 NULL, &lib, take, &g);
	check(g.n == 0u, "no symbols, no functions, no units - and no byte carve");

	/* a region that is not offered a function at a time is cut by bytes, whole */
	{
		uint32_t i;
		uint64_t at = 0;
		struct kof_range e2 = { 0, 10000 };
		static uint8_t big[10000];
		uint32_t s = 7;

		for (i = 0; i < sizeof big; i++) {
			s = s * 1103515245u + 12345u;
			big[i] = (uint8_t)(s >> 16);
		}
		lib.span[0].off = 3000; lib.span[0].len = 2000; lib.n = 1;
		memset(&g, 0, sizeof g);
		kof_plague_units(big, sizeof big, KOF_FMT_ELF, KOF_SCAN_ELF_DATA,
				 &e2, 1, &fs, &lib, take, &g);
		for (i = 0; i < g.n; i++) {
			check(g.off[i] == at, "the pieces do not tile the region");
			at = g.off[i] + g.len[i];
			check(!(g.off[i] < 3000u && g.off[i] + g.len[i] > 3000u),
			      "a piece spans the join into the library");
			check((g.off[i] >= 3000u && g.off[i] < 5000u) ==
			      (g.side[i] == KOF_PLAGUE_SIDE_LIB),
			      "a piece is on the wrong side");
		}
		check(at == sizeof big && g.n > 2u, "the region is not covered");
		/* the same call again gives the same cut: it is deterministic */
		{
			struct got h;

			memset(&h, 0, sizeof h);
			kof_plague_units(big, sizeof big, KOF_FMT_ELF,
					 KOF_SCAN_ELF_DATA, &e2, 1, &fs, &lib,
					 take, &h);
			check(h.n == g.n && !memcmp(h.off, g.off, g.n * sizeof *g.off),
			      "the cut is not the same twice");
		}
	}
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void pe_functions(void)
{
	static uint8_t file[0x1400];
	static struct kof_pe_info p;
	struct kof_func_set fs;
	uint8_t *t = file + 0x200 + 0x800;      /* the table, at RVA 0x1800 */

	memset(file, 0x90, sizeof file);
	memset(&p, 0, sizeof p);
	p.valid = 1; p.pe32_plus = 1; p.machine = 0x8664u;
	p.sec_count = 1;
	p.sec[0].mem_rva = 0x1000; p.sec[0].mem_size = 0x1000;
	p.sec[0].file_off = 0x200; p.sec[0].file_size = 0x1000;
	p.dir[KOF_PE_DIR_EXCEPTION].rva = 0x1800;
	p.dir[KOF_PE_DIR_EXCEPTION].size = 4u * 12u;
	/* unwind info: at 0x1900 no flags, at 0x1920 CHAININFO */
	file[0x200 + 0x900] = 0x01;
	file[0x200 + 0x920] = 0x01 | (0x4u << 3);
	put32(t + 0,  0x1000); put32(t + 4,  0x1080); put32(t + 8,  0x1900);
	put32(t + 12, 0x1100); put32(t + 16, 0x1150); put32(t + 20, 0x1900);
	put32(t + 24, 0x1200); put32(t + 28, 0x1280); put32(t + 32, 0x1920); /* a fragment */
	put32(t + 36, 0x1300); put32(t + 40, 0x1380); put32(t + 44, 0x1901); /* indirect */

	kof_pe_funcs_build(kof_buf_make(file, sizeof file), &p, &fs);
	check(fs.n == 2u, "the functions of a PE are its unchained, direct entries");
	check(fs.n == 2u && fs.v[0].off == 0x200u + 0x0u && fs.v[0].len == 0x80u &&
	      fs.v[1].off == 0x300u && fs.v[1].len == 0x50u,
	      "a function is where its RVA lands in the file, as long as it says");
	kof_funcs_free(&fs);

	p.machine = 0x14cu;
	kof_pe_funcs_build(kof_buf_make(file, sizeof file), &p, &fs);
	check(fs.n == 0u, "a 32-bit PE has no table, so it has no functions");
	p.machine = 0x8664u;
	p.dir[KOF_PE_DIR_EXCEPTION].size = 0xffffffffu;   /* more than the file holds */
	kof_pe_funcs_build(kof_buf_make(file, sizeof file), &p, &fs);
	check(fs.n >= 2u, "a table the file cuts short is read as far as it goes");
	kof_funcs_free(&fs);
}

/*
 * DATA IN A CODE REGION: strings the function walk never reaches are offered as
 * clusters - strings with at most 128 bytes between them are one block, a gap
 * wider than that starts the next, and under 64 bytes is not a block.
 */
static size_t put_str(uint8_t *p, size_t at, const char *s)
{
	size_t n = strlen(s) + 1u;

	memcpy(p + at, s, n);
	return at + n;
}

static void data_in_code(void)
{
	static uint8_t obj[4096];
	struct kof_range ext = { 0, 4000 };
	struct kof_func_set fs;
	struct got g;
	size_t i, at, first_from, first_to;

	memset(&fs, 0, sizeof fs);
	for (i = 0; i < sizeof obj; i++)               /* "code": no printable run */
		obj[i] = (uint8_t)(0x80u | (i * 5u & 0x3fu) | 0x40u);
	at = 300;
	first_from = at;
	at = put_str(obj, at, "GET /index.html HTTP/1.1");
	at = put_str(obj, at, "Mozilla/5.0 (X11; Linux x86_64)");
	at += 100;                                      /* a table, inside the gap */
	at = put_str(obj, at, "/bin/busybox wget http://");
	first_to = at;
	at += 400;                                      /* wider than the gap */
	at = put_str(obj, at, "short one only");        /* 15 bytes: not a block */

	memset(&g, 0, sizeof g);
	kof_plague_units(obj, sizeof obj, KOF_FMT_ELF, KOF_SCAN_ELF_CODE, &ext, 1,
			 &fs, NULL, take, &g);
	check(g.n == 1u, "one cluster; the short string alone is not a block");
	if (g.n == 1u) {
		check(g.off[0] == first_from && g.len[0] == first_to - first_from,
		      "the strings and the table between them are one block");
		check(g.side[0] == KOF_PLAGUE_SIDE_USER, "on the author's side");
	}
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	functions();
	pe_functions();
	data_in_code();
	if (failures) {
		printf("plague units: %d failure(s)\n", failures);
		return 1;
	}
	printf("plague units: function units grouped and filtered, byte pieces tile "
	       "and split at the library, a PE's functions from .pdata - ok\n");
	return 0;
}
