/*
 * mutation_units - how an object is cut into the units a block is made from, and
 * where a PE's functions come from.
 *
 * The scanner and the authoring tool both call kgenome_mutation_units, so what this
 * pins is the cut itself: a function region yields ONE unit per function - no
 * minimum, no grouping; only the library's and those outside the region are not offered, none when the symbols are absent -
 * and any other region tiles exactly, split at a library boundary with a side
 * on every piece.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detectors/mutations/kofmutation.h"
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
		const struct kgenome_func *first)
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
	struct kgenome_func v[6] = {
		{ 100, 300, 0, 0 },   /* a function */
		{ 500, 100, 0, 0 },   /* small, next to the next one: still a unit of its own (was grouped with it) ... */
		{ 610, 100, 0, 0 },   /* ... and so is this one */
		{ 2000, 40, 0, 0 },   /* 40 bytes: a unit, there is no minimum size */
		{ 3000, 200, 0, 0 },  /* the library's */
		{ 5000, 100, 0, 0 },  /* outside the region */
	};
	struct kgenome_func_set fs;
	struct kof_range ext = { 0, 4000 };
	struct kgenome_true_all lib;
	struct got g;
	struct kgenome_mutation_tally tally;

	memset(&tally, 0, sizeof tally);
	memset(&fs, 0, sizeof fs);
	fs.v = v; fs.n = 6;
	memset(&lib, 0, sizeof lib);
	lib.span[0].off = 3100; lib.span[0].len = 50; lib.n = 1;

	memset(&g, 0, sizeof g);
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj,
			.n_obj = sizeof obj,
			.format = KOF_FMT_ELF,
			.mask = KGENOME_SCAN_ELF_CODE,
			.ext = &ext,
			.n_ext = 1,
			.funcs = &fs,
			.lib = &lib,
			.fn = take,
			.user = &g,
			.tally = &tally,
		});
	check(g.n == 4u, "the units of a function region are its functions, the library's and the outside one excepted");
	/* FP-18: what the cut left out is COUNTED (it was dropped with no word). RED on the base: there is no tally; the units themselves did not change */
	check(tally.funcs == 6u && tally.units == 4u && tally.outside == 1u && tally.lib == 1u,
	      "the cut says how many functions it offered, left outside the region and left to the library");
	check(g.n >= 1u && g.off[0] == 100u && g.len[0] == 300u,
	      "a function is a unit of its own extent");
	check(g.n >= 4u && g.off[1] == 500u && g.len[1] == 100u && g.off[2] == 610u && g.len[2] == 100u,
	      "small functions that sit together are one unit each");
	check(g.n >= 4u && g.off[3] == 2000u && g.len[3] == 40u, "a function of 40 bytes is a unit");
	check(g.side[0] == KGENOME_MUTATION_SIDE_USER, "a function is on the author's side");

	memset(&g, 0, sizeof g);
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj,
			.n_obj = sizeof obj,
			.format = KOF_FMT_ELF,
			.mask = KGENOME_SCAN_ELF_CODE,
			.ext = &ext,
			.n_ext = 1,
			.funcs = NULL,
			.lib = &lib,
			.fn = take,
			.user = &g,
		});
	check(g.n == 0u, "no symbols, no functions, no units - and no byte carve");
	/* a tally is added to by every function region the request cuts, and a stopped walk counts only what it met; a NULL tally is the ordinary call (the rows above) */
	{
		struct kgenome_mutation_tally t2;
		struct kof_range cut = { 100, 250 };         /* [100, 350): function 0 (100..400) straddles the end of the extent */

		memset(&t2, 0, sizeof t2);
		memset(&g, 0, sizeof g);
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = obj, .n_obj = sizeof obj, .format = KOF_FMT_ELF, .mask = KGENOME_SCAN_ELF_CODE,
				.ext = &cut, .n_ext = 1, .funcs = &fs, .lib = &lib, .fn = take, .user = &g, .tally = &t2,
			});
		check(t2.funcs == 6u && t2.units == 0u && t2.outside == 6u && t2.lib == 0u,
		      "a function not wholly inside an extent is counted outside, whatever the library does");
	}
	{
		struct kof_mutation_ctx c;

		memset(&c, 0, sizeof c);
		kof_mutation_note_dropped(&c, 0, 0);
		check(!(c.status & KOF_MTN_S_FUNC_DROPPED), "nothing dropped, nothing said");
		kof_mutation_note_dropped(&c, 2, 3);
		check((c.status & KOF_MTN_S_FUNC_DROPPED) && c.funcs_lib == 2u && c.funcs_out == 3u, "a dropped function says so on the object");
		kof_mutation_note_dropped(NULL, 1, 1);
	}

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
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = big,
				.n_obj = sizeof big,
				.format = KOF_FMT_ELF,
				.mask = KGENOME_SCAN_ELF_DATA,
				.ext = &e2,
				.n_ext = 1,
				.funcs = &fs,
				.lib = &lib,
				.fn = take,
				.user = &g,
			});
		for (i = 0; i < g.n; i++) {
			check(g.off[i] == at, "the pieces do not tile the region");
			at = g.off[i] + g.len[i];
			check(!(g.off[i] < 3000u && g.off[i] + g.len[i] > 3000u),
			      "a piece spans the join into the library");
			check((g.off[i] >= 3000u && g.off[i] < 5000u) ==
			      (g.side[i] == KGENOME_MUTATION_SIDE_LIB),
			      "a piece is on the wrong side");
		}
		check(at == sizeof big && g.n > 2u, "the region is not covered");
		/* the same call again gives the same cut: it is deterministic */
		{
			struct got h;

			memset(&h, 0, sizeof h);
			kgenome_mutation_units(&(const struct kgenome_mutation_req){
					.p = big,
					.n_obj = sizeof big,
					.format = KOF_FMT_ELF,
					.mask = KGENOME_SCAN_ELF_DATA,
					.ext = &e2,
					.n_ext = 1,
					.funcs = &fs,
					.lib = &lib,
					.fn = take,
					.user = &h,
				});
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
	static struct kgenome_pe_info p;
	struct kgenome_func_set fs;
	uint8_t *t = file + 0x200 + 0x800;      /* the table, at RVA 0x1800 */

	memset(file, 0x90, sizeof file);
	memset(&p, 0, sizeof p);
	p.valid = 1; p.pe32_plus = 1; p.machine = 0x8664u;
	p.sec_count = 1;
	p.sec[0].mem_rva = 0x1000; p.sec[0].mem_size = 0x1000;
	p.sec[0].file_off = 0x200; p.sec[0].file_size = 0x1000;
	p.sec[0].perm = KGENOME_PE_PERM_X;      /* the section is code: an exception table entry whose function is in a section that does not execute is refused (fntab_pe_pdata.c) */
	p.dir[KGENOME_PE_DIR_EXCEPTION].rva = 0x1800;
	p.dir[KGENOME_PE_DIR_EXCEPTION].size = 4u * 12u;
	/* unwind info: at 0x1900 no flags, at 0x1920 CHAININFO */
	file[0x200 + 0x900] = 0x01;
	file[0x200 + 0x920] = 0x01 | (0x4u << 3);
	put32(t + 0,  0x1000); put32(t + 4,  0x1080); put32(t + 8,  0x1900);
	put32(t + 12, 0x1100); put32(t + 16, 0x1150); put32(t + 20, 0x1900);
	put32(t + 24, 0x1200); put32(t + 28, 0x1280); put32(t + 32, 0x1920); /* a fragment */
	put32(t + 36, 0x1300); put32(t + 40, 0x1380); put32(t + 44, 0x1901); /* indirect */

	kgenome_pe_funcs_build(kof_buf_make(file, sizeof file), &p, &fs);
	/* the entry with an indirect unwind address (low bit set) is a function with its own Begin and End: its info is not read (PDATA-1: it used to be dropped without a word); the chained one is a fragment */
	check(fs.n == 3u, "the functions of a PE are its unchained entries, the indirect one included");
	check(fs.n == 3u && fs.v[0].off == 0x200u + 0x0u && fs.v[0].len == 0x80u &&
	      fs.v[1].off == 0x300u && fs.v[1].len == 0x50u && fs.v[2].off == 0x500u && fs.v[2].len == 0x80u,
	      "a function is where its RVA lands in the file, as long as it says");
	kgenome_funcs_free(&fs);

	p.machine = 0x14cu;
	kgenome_pe_funcs_build(kof_buf_make(file, sizeof file), &p, &fs);
	check(fs.n == 0u, "a 32-bit PE has no table, so it has no functions");
	p.machine = 0x8664u;
	p.dir[KGENOME_PE_DIR_EXCEPTION].size = 0xffffffffu;   /* more than the file holds */
	kgenome_pe_funcs_build(kof_buf_make(file, sizeof file), &p, &fs);
	check(fs.n >= 2u, "a table the file cuts short is read as far as it goes");
	kgenome_funcs_free(&fs);
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
	struct kgenome_func_set fs;
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
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj,
			.n_obj = sizeof obj,
			.format = KOF_FMT_ELF,
			.mask = KGENOME_SCAN_ELF_CODE,
			.ext = &ext,
			.n_ext = 1,
			.funcs = &fs,
			.lib = NULL,
			.fn = take,
			.user = &g,
		});
	check(g.n == 1u, "one cluster; the short string alone is not a block");
	if (g.n == 1u) {
		check(g.off[0] == first_from && g.len[0] == first_to - first_from,
		      "the strings and the table between them are one block");
		check(g.side[0] == KGENOME_MUTATION_SIDE_USER, "on the author's side");
	}

	/* A library span across the middle of the cluster cuts it like any other
	 * unit: the author's strings stay on the author's side. */
	{
		struct kgenome_true_all lib;
		size_t cut = first_from + 40;

		memset(&lib, 0, sizeof lib);
		lib.span[0].off = cut; lib.span[0].len = 30; lib.n = 1;
		memset(&g, 0, sizeof g);
		kgenome_mutation_units(&(const struct kgenome_mutation_req){
				.p = obj,
				.n_obj = sizeof obj,
				.format = KOF_FMT_ELF,
				.mask = KGENOME_SCAN_ELF_CODE,
				.ext = &ext,
				.n_ext = 1,
				.funcs = &fs,
				.lib = &lib,
				.fn = take,
				.user = &g,
			});
		check(g.n == 3u, "a library span inside the cluster cuts it in three");
		if (g.n == 3u) {
			check(g.off[0] == first_from && g.len[0] == 40 &&
			      g.side[0] == KGENOME_MUTATION_SIDE_USER,
			      "the part before the library is the author's");
			check(g.off[1] == cut && g.len[1] == 30 &&
			      g.side[1] == KGENOME_MUTATION_SIDE_LIB,
			      "the library's own bytes are on its side");
			check(g.off[2] == cut + 30 && g.side[2] == KGENOME_MUTATION_SIDE_USER &&
			      g.off[2] + g.len[2] == first_to,
			      "and the part after is the author's again");
		}
	}
}

/*
 * A data region is cut by content, but a string is never cut: a cluster of
 * strings is one unit, and the cut falls only in the bytes around it
 * (1794cf09...: a 14011-byte .rodata cluster was cut mid-text).
 */
static void data_strings(void)
{
	static uint8_t obj[60000];
	struct kof_range e = { 0, sizeof obj };
	struct kgenome_func_set fs;
	struct kgenome_true_all lib;
	struct got g;
	uint32_t s = 11, i, j, hit = 0;
	uint64_t at = 0;

	memset(&fs, 0, sizeof fs);
	memset(&lib, 0, sizeof lib);
	for (i = 0; i < sizeof obj; i++) {
		s = s * 1103515245u + 12345u;
		obj[i] = (uint8_t)(s >> 16) | 0x80;	/* never printable */
	}
	/* 20000 bytes of strings from 20000: far larger than a cut piece */
	for (i = 20000; i < 40000; ) {
		for (j = 0; j < 40 && i < 40000; j++, i++)
			obj[i] = 'a' + (uint8_t)(j % 26);
		obj[i - 1] = 0;
	}
	memset(&g, 0, sizeof g);
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj,
			.n_obj = sizeof obj,
			.format = KOF_FMT_ELF,
			.mask = KGENOME_SCAN_ELF_DATA,
			.ext = &e,
			.n_ext = 1,
			.funcs = &fs,
			.lib = &lib,
			.fn = take,
			.user = &g,
		});
	for (i = 0; i < g.n; i++) {
		check(g.off[i] == at, "the units do not tile the region");
		at = g.off[i] + g.len[i];
		/* a unit boundary inside the strings must sit after a NUL */
		for (j = 0; j < 2; j++) {
			uint64_t b = j ? g.off[i] + g.len[i] : g.off[i];

			if (b > 20000u && b < 40000u)
				check(obj[b - 1] == 0, "a string was cut");
		}
		if (g.off[i] == 20000u)
			hit = 1;
	}
	check(at == sizeof obj, "the region is not covered");
	check(hit, "the string cluster does not start a unit");
}


/*
 * A FIXED EXTENT IS ONE UNIT. A view's decoded strings are not printable, so cutting
 * the view again would break a parent's cluster into pieces; the producer says
 * where the unit is and the cut leaves it whole, cutting only around it.
 */
static void fixed_units(void)
{
	static uint8_t obj[60000];
	struct kof_range e = { 0, sizeof obj };
	struct kof_range fx[2] = { { 5000, 600 }, { 20100, 900 } };
	struct kgenome_func_set fs;
	struct kgenome_true_all lib;
	struct got g;
	uint32_t s = 11, i, j, seen = 0;
	uint64_t at = 0;

	memset(&fs, 0, sizeof fs);
	memset(&lib, 0, sizeof lib);
	for (i = 0; i < sizeof obj; i++) {
		s = s * 1103515245u + 12345u;
		obj[i] = (uint8_t)(s >> 16) | 0x80;
	}
	for (i = 20000; i < 40000; ) {          /* strings across the second fixed extent */
		for (j = 0; j < 40 && i < 40000; j++, i++)
			obj[i] = 'a' + (uint8_t)(j % 26);
		obj[i - 1] = 0;
	}
	memset(&g, 0, sizeof g);
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj, .n_obj = sizeof obj, .format = KOF_FMT_ELF,
			.mask = KGENOME_SCAN_ELF_DATA, .ext = &e, .n_ext = 1,
			.funcs = &fs, .lib = &lib, .fixed = fx, .n_fixed = 2,
			.fn = take, .user = &g,
		});
	for (i = 0; i < g.n; i++) {
		check(g.off[i] == at, "the fixed units leave a gap or an overlap");
		at = g.off[i] + g.len[i];
		for (j = 0; j < 2; j++) {
			uint64_t a = fx[j].off, b = fx[j].off + fx[j].len;

			if (g.off[i] == a && g.len[i] == fx[j].len)
				seen++;
			check(!(g.off[i] < a && g.off[i] + g.len[i] > a) &&
			      !(g.off[i] < b && g.off[i] + g.len[i] > b),
			      "a unit spans the edge of a fixed extent");
		}
	}
	check(at == sizeof obj, "the region is not covered with fixed units in it");
	check(seen == 2u, "a fixed extent is not exactly one unit");

	/* A library span through a fixed unit cuts it like any other unit. */
	lib.span[0].off = 5200; lib.span[0].len = 100; lib.n = 1;
	memset(&g, 0, sizeof g);
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj, .n_obj = sizeof obj, .format = KOF_FMT_ELF,
			.mask = KGENOME_SCAN_ELF_DATA, .ext = &e, .n_ext = 1,
			.funcs = &fs, .lib = &lib, .fixed = fx, .n_fixed = 1,
			.fn = take, .user = &g,
		});
	for (i = 0, seen = 0; i < g.n; i++)
		if (g.off[i] >= 5000u && g.off[i] < 5600u)
			seen++;
	check(seen == 3u, "a library span inside a fixed unit does not cut it in three");

	/* In a region offered a function at a time only strings are cut, and the
	 * fixed unit is still one unit. */
	lib.n = 0;
	memset(&g, 0, sizeof g);
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj, .n_obj = sizeof obj, .format = KOF_FMT_ELF,
			.mask = KGENOME_SCAN_ELF_CODE, .ext = &e, .n_ext = 1,
			.funcs = &fs, .lib = NULL, .fixed = fx, .n_fixed = 1,
			.fn = take, .user = &g,
		});
	for (i = 0, seen = 0; i < g.n; i++)
		if (g.off[i] == 5000u && g.len[i] == 600u)
			seen++;
	check(seen == 1u, "a fixed unit in a function region is not offered whole");
}

/*
 * FUNCTION UNITS ARE SIGNED BY SHAPE, NOT BY WINDOWS (kgenome_mutation_signature).
 * Over a code region that holds two functions (varying bytes, so a window sketch WOULD exist) and a string cluster:
 * every unit that is functions (first != NULL) answers KGENOME_MUTATION_SIG_CFG and has no window hashes - the
 * window unit_minhash call leaves its output untouched and answers 0 - and the cluster (first == NULL) keeps its windows,
 * equal to the plain minhash of the same bytes.
 */
struct sigs {
	uint32_t n_fn, n_data, fn_hashes, data_ok;
	const uint8_t *p;
};

static int sig_take(void *user, uint64_t off, uint64_t len, uint32_t side, const struct kgenome_func *first)
{
	struct sigs *g = user;
	uint32_t out[KGENOME_MUTATION_MINHASH_K], ref[KGENOME_MUTATION_MINHASH_K], k, n;

	(void)side;
	for (k = 0; k < KGENOME_MUTATION_MINHASH_K; k++)
		out[k] = 0xdeadbeefu;
	n = kgenome_mutation_unit_minhash(first, g->p + off, len, out);
	if (first) {
		g->n_fn++;
		check(kgenome_mutation_signature(first) == KGENOME_MUTATION_SIG_CFG, "a function unit has a CFG signature (kof_cfgsign_function), not windows");
		check(n == 0u, "a function unit is not sketched");
		for (k = 0; k < KGENOME_MUTATION_MINHASH_K; k++)
			g->fn_hashes += out[k] != 0xdeadbeefu;
		/* the bytes WOULD have a sketch: it is the switch that withholds it, not the content */
		check(kgenome_mutation_minhash(g->p + off, len, ref) >= KGENOME_MUTATION_MIN_HASH, "the function bytes do vary");
	} else {
		g->n_data++;
		check(kgenome_mutation_signature(first) == KGENOME_MUTATION_SIG_WINDOWS, "a unit that is not functions has windows");
		check(n == kgenome_mutation_minhash(g->p + off, len, ref) && !memcmp(out, ref, n * sizeof out[0]),
		      "a data unit's sketch is the plain minhash");
		g->data_ok += n >= KGENOME_MUTATION_MIN_HASH;
	}
	return 0;
}

static void signatures(void)
{
	static uint8_t obj[8192];
	struct kgenome_func v[2] = { { 100, 300, 0, 0 }, { 600, 300, 0, 0 } };
	struct kgenome_func_set fs;
	struct kof_range ext = { 0, 4096 };
	struct sigs g;
	uint32_t s = 0x1234567u, i;

	for (i = 0; i < sizeof obj; i++) {
		s ^= s << 13; s ^= s >> 17; s ^= s << 5;
		obj[i] = (uint8_t)s;
	}
	/* a cluster of printable strings after the functions: data inside a code region */
	for (i = 0; i < 40; i++)
		memcpy(obj + 2000 + i * 20u, "usr/bin/some-string-", 19), obj[2000 + i * 20u + 19u] = 0;
	memset(&fs, 0, sizeof fs);
	fs.v = v; fs.n = 2;
	memset(&g, 0, sizeof g);
	g.p = obj;
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj, .n_obj = sizeof obj, .format = KOF_FMT_ELF, .mask = KGENOME_SCAN_ELF_CODE,
			.ext = &ext, .n_ext = 1, .funcs = &fs, .fn = sig_take, .user = &g,
		});
	check(g.n_fn == 2u, "both function units are still listed");
	check(g.fn_hashes == 0u, "no function unit carries a window hash");
	check(g.n_data >= 1u && g.data_ok >= 1u, "the string cluster of the code region keeps its windows");
	/* a region that is not cut by function: its pieces have windows */
	memset(&g, 0, sizeof g);
	g.p = obj;
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = obj, .n_obj = sizeof obj, .format = KOF_FMT_ELF, .mask = KGENOME_SCAN_ELF_DATA,
			.ext = &ext, .n_ext = 1, .funcs = &fs, .fn = sig_take, .user = &g,
		});
	check(g.n_fn == 0u && g.n_data >= 1u && g.data_ok >= 1u, "a data region is cut in pieces that keep their windows");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	functions();
	pe_functions();
	data_in_code();
	data_strings();
	fixed_units();
	signatures();
	if (failures) {
		printf("mutation units: %d failure(s)\n", failures);
		return 1;
	}
	printf("mutation units: one function unit per function, byte pieces tile "
	       "and split at the library, a PE's functions from .pdata - ok\n");
	return 0;
}
