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
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"
#include "../../libkofeng/kofcore/kofmod/pe.h"
#include "../../libkofeng/kofcore/kofmod/script.h"
#include <celllysis/script_funcs.h>
#include <textual/textual.h>

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
 * FUNCTION UNITS HAVE NO SIGNATURE (kgenome_mutation_signature; CFG signing disabled by the owner 2026-11-15).
 * FLIPPED 2026-11-15: this row said KGENOME_MUTATION_SIG_CFG (function units signed by shape); it now pins SIG_NONE, the owner's
 * default (nothing in place of the CFG sketch: TODO(owner) at kgenome_mutation_signature). RED on the old code: SIG_CFG was answered.
 * Over a code region that holds two functions (varying bytes, so a window sketch WOULD exist) and a string cluster:
 * every unit that is functions (first != NULL) answers KGENOME_MUTATION_SIG_NONE and has no window hashes - the
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
		check(kgenome_mutation_signature(first) == KGENOME_MUTATION_SIG_NONE, "a function unit has no signature (" KGENOME_MUTATION_SIG_NONE_WHY ")");
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

/*
 * SCRIPT FUNCTIONS (owner, 2026-11-05: "tokenize cung phai nhan dien function... hien thi trong
 * kofviewer trong bang mutation"): a function a script's own declaration shape names is ONE UNIT,
 * the same no-minimum/no-grouping policy as a binary's. RED on the base: kgenome_mutation_by_function
 * answered 0 for every KOF_FMT_SCRIPT region (the "a script is read by its lexer, so it has no
 * functions" assumption objctx_diag_text.c stated outright), so a PHP file's BODY had no function
 * table at all and every unit - a 3-line function included - came from the generic content-defined
 * cut, unaware a function boundary was there.
 */
struct sfn_got {
	uint64_t off[32], len[32];
	uint8_t  kind[32];
	uint32_t n;
};

static int sfn_take(void *user, uint64_t off, uint64_t len, uint32_t side, const struct kgenome_func *first)
{
	struct sfn_got *g = user;

	(void)side;
	if (g->n < 32u) {
		g->off[g->n] = off;
		g->len[g->n] = len;
		g->kind[g->n] = first ? first->kind : 0xffu;
		g->n++;
	}
	return 0;
}

static void script_functions(void)
{
	static const char php[] =
		"<?php\n"
		"function tiny($a) {\n"
		"  return $a + 1;\n"
		"}\n"
		"function outer($x) {\n"
		"  function inner($y) { return $y * 2; }\n"
		"  return inner($x);\n"
		"}\n"
		"$z = 1 + 2;\n";
	struct kgenome_func_set fs;
	struct kof_range ext = { 0, (uint64_t)(sizeof php - 1u) };
	struct sfn_got g;
	const char *tiny_at = strstr(php, "function tiny");
	const char *outer_at = strstr(php, "function outer");

	/*
	 * ALL, NOT BODY: a script the lib lexes (every one kgenome_script_funcs_build can be asked
	 * about) is regionless (kof_obj_regionless, kofformat.c) - the engine's own "no regions" cut
	 * credits it as KOF_SCAN_ALL unconditionally, never by resolving BODY/HEADER/MARKUP, so that
	 * is the one mask this ever fires on. Confirmed the hard way (2026-11-05): an earlier version
	 * of this check asked for SCRIPT_BODY and PASSED here (a direct, isolated call does not know
	 * the engine never resolves that mask for a real object) while a live kofexaminer --blocks run
	 * on a real PHP file showed zero function units - this row is this task's own reminder that an
	 * isolated unit test is not the end-to-end proof the brief asked for. */
	check(kgenome_mutation_by_function(KOF_FMT_SCRIPT, KOF_SCAN_ALL) != 0,
	      "a regionless script's one region (ALL) is cut a function at a time");
	check(kgenome_mutation_by_function(KOF_FMT_SCRIPT, KOF_SCAN_SCRIPT_BODY) == 0,
	      "BODY itself is never asked: kof_obj_regionless makes it unreachable for a lexed script");

	/* NESTING (PHP allows a function declared inside another): both keywords are found, but the
	 * dedup inside kgenome_script_funcs_build keeps only the outermost - the same containment
	 * rule kgenome_fntab_merge gives a binary's contained symbol, needed because
	 * kgenome_funcs_at's binary search (shared by every consumer of struct kgenome_func_set, not
	 * only mutation) assumes a later entry's end never dips below an earlier one's. A documented
	 * DECISION (script_funcs.c's header), not an oversight: inner's bytes are still hashed, as
	 * part of outer's unit, not lost. */
	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	check(fs.n == 2u, "outer is kept, inner is merged into it: two units, not three");
	if (fs.n == 2u && tiny_at && outer_at) {
		const char *tiny_close = strchr(tiny_at, '}');
		uint64_t tiny_off = (uint64_t)(tiny_at - php), outer_off = (uint64_t)(outer_at - php);

		check(fs.v[0].off == tiny_off && fs.v[1].off == outer_off, "sorted by offset, tiny then outer");
		check(tiny_close != NULL && fs.v[0].len == (uint64_t)(tiny_close - tiny_at) + 1u,
		      "tiny's unit runs exactly to its own closing brace");
		check(fs.v[0].kind == KGENOME_FN_SCRIPT && fs.v[1].kind == KGENOME_FN_SCRIPT,
		      "a script entry carries the SCRIPT kind, never a binary one");
		/*
		 * RED on the code before this patch (struct kgenome_func had no name field at all, so
		 * kof_func_name - the engine's ONE spelling, funcs.h's own header, the same call
		 * kofexaminer_blocks.c's --blocks and kofviewer's Blocks table both make) always fell
		 * back to fcn_<offset> for a script function. GREEN here: the owner's whole ask was
		 * "connect the mutation blocks to the function DISPLAY for scripting languages" -
		 * this is that connection, through the one function every display path already calls,
		 * not a new one.
		 */
		{
			char nm0[32], nm1[32], want0[32], want1[32];

			kof_fcn_name(fs.v[0].off, want0, sizeof want0);
			kof_fcn_name(fs.v[1].off, want1, sizeof want1);
			check(kof_func_name(&fs.v[0], NULL, 0, (const uint8_t *)php, sizeof php - 1u, nm0, sizeof nm0) == 1 &&
			      !strcmp(nm0, "tiny"), "tiny's own declared name, not fcn_<offset>");
			check(kof_func_name(&fs.v[1], NULL, 0, (const uint8_t *)php, sizeof php - 1u, nm1, sizeof nm1) == 1 &&
			      !strcmp(nm1, "outer"), "outer's own declared name, not fcn_<offset>, and not inner's (the nested one the dedup folded away)");
			/* a script function is never confused with the made-up name of its OWN offset */
			check(strcmp(nm0, want0) != 0 && strcmp(nm1, want1) != 0,
			      "a real declared name is never the same text as the made-up fcn_<offset> one");
			/* data_n too small for the captured span (a caller handing in fewer bytes than the
			 * table was built from, or a mismatched object): falls back cleanly, never reads
			 * past what it was given. */
			check(kof_func_name(&fs.v[0], NULL, 0, (const uint8_t *)php, fs.v[0].off, nm0, sizeof nm0) == 0 &&
			      !strcmp(nm0, want0), "a short data_n is refused, not read out of bounds");
			/* NULL data with a real name_len: the same clean fallback, not a NULL deref. */
			check(kof_func_name(&fs.v[0], NULL, 0, NULL, 0, nm0, sizeof nm0) == 0 && !strcmp(nm0, want0),
			      "no object bytes at all: fcn_<offset>, not a crash");
		}
	}

	/*
	 * THE SAME TABLE THROUGH kgenome_mutation_units, mask ALL (the only mask a script ever runs
	 * this on - see above): each surviving function is its OWN exact unit, carrying its
	 * kgenome_func back: not folded into, or replaced by, a content-defined slice. The top-level
	 * code around them ("$z = 1 + 2;", the "<?php" line, the blank lines between the functions) is
	 * NOT dropped either - unlike ELF/PE, a script's leftover bytes are ordinary code and keep the
	 * generic cut (script_remainder, mutation_units.c), so other, first-NULL pieces are expected
	 * here too and are not counted against the function units.
	 */
	memset(&g, 0, sizeof g);
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = (const uint8_t *)php, .n_obj = sizeof php - 1u,
			.format = KOF_FMT_SCRIPT, .mask = KOF_SCAN_ALL,
			.ext = &ext, .n_ext = 1, .funcs = &fs, .fn = sfn_take, .user = &g,
		});
	{
		uint32_t i, n_fn = 0;
		int tiny_seen = 0, outer_seen = 0;

		for (i = 0; i < g.n; i++) {
			if (g.kind[i] != KGENOME_FN_SCRIPT)
				continue;
			n_fn++;
			if (g.off[i] == fs.v[0].off && g.len[i] == fs.v[0].len)
				tiny_seen = 1;
			if (g.off[i] == fs.v[1].off && g.len[i] == fs.v[1].len)
				outer_seen = 1;
		}
		check(n_fn == 2u, "exactly the two surviving functions come back as function units, no more no less");
		check(tiny_seen && outer_seen, "each function unit is the function's own exact span, not a content-defined slice of it");
		check(g.n > n_fn, "the top-level code around the functions still gets units of its own (not dropped the way ELF/PE's leftover CODE bytes are)");
	}
	kgenome_funcs_free(&fs);

	/*
	 * SIGNATURE: a script function unit is windows, never CFG. RED on a kgenome_mutation_signature
	 * that only asked "is first non-NULL" (true before KGENOME_FN_SCRIPT existed, when every
	 * non-NULL first WAS a binary function): that version answers CFG here, which would have sent
	 * PHP text into kof_cfgsign_function to be decoded as machine code.
	 */
	{
		struct kgenome_func sf;
		uint32_t hashes[KGENOME_MUTATION_MINHASH_K], nh;

		memset(&sf, 0, sizeof sf);
		sf.off = 0; sf.len = sizeof php - 1u; sf.kind = KGENOME_FN_SCRIPT;
		check(kgenome_mutation_signature(&sf) == KGENOME_MUTATION_SIG_WINDOWS,
		      "a script function unit's signature is windows, not CFG - no script CFG exists");
		nh = kgenome_mutation_unit_minhash(&sf, (const uint8_t *)php, sf.len, hashes);
		check(nh > 0u, "its minhash is computed like any window unit, not refused");
	}

	/* NO FUNCTIONS AT ALL: a language this build has no lexer for (every lexed language has a
	 * strategy since 2026-11-14, the island package) and a PHP file with none both answer an
	 * empty, COMPLETE table - the existing content-defined fallback is unaffected either way. */
	{
		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_COUNT, (const uint8_t *)php, sizeof php - 1u, &fs);
		check(fs.n == 0u && fs.state == KGENOME_FNTAB_COMPLETE && fs.ccase == KGENOME_FNTAB_C_NONE,
		      "a language with no strategy answers empty and COMPLETE, like a format kgenome_funcs_build does not know");
		kgenome_funcs_free(&fs);
	}
	{
		static const char plain[] = "<?php\n$a = 1;\n$b = 2;\n";

		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)plain, sizeof plain - 1u, &fs);
		check(fs.n == 0u, "a PHP file with no functions at all: an empty table, the fallback untouched");
		kgenome_funcs_free(&fs);
	}

	/* TRUNCATED: a function whose body never closes is still listed - run to the end of the buffer
	 * and flagged open, not dropped (rule 4: a cap must not delete evidence). */
	{
		static const char trunc[] = "<?php\nfunction f($a) {\n  return $a;\n";

		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)trunc, sizeof trunc - 1u, &fs);
		check(fs.n == 1u && fs.v[0].len == sizeof trunc - 1u - fs.v[0].off,
		      "an unterminated function runs to the end of the buffer");
		check(fs.n == 1u && (fs.v[0].flags & KGENOME_FN_F_END_OPEN) != 0,
		      "...and says so (END_OPEN), the convention a binary's open-ended entry uses");
		check(fs.state == KGENOME_FNTAB_PARTIAL, "the table says it is partial, not silently complete");
		kgenome_funcs_free(&fs);
	}

	/* MANY SMALL FUNCTIONS adjacent to each other: no grouping - the binary side measured that
	 * grouping costs start recall (mutation_units.c's own header), and nothing here groups either. */
	{
		static const char many[] =
			"<?php\nfunction a(){return 1;}\nfunction b(){return 2;}\nfunction c(){return 3;}\n";

		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)many, sizeof many - 1u, &fs);
		check(fs.n == 3u, "three tiny adjacent functions are three units, never grouped into one");
		kgenome_funcs_free(&fs);
	}

	/*
	 * A FUNCTION BODY THAT STRADDLES WHAT WOULD HAVE BEEN A CONTENT-CUT WINDOW BOUNDARY: the point of
	 * this feature. Padded past KGENOME_MUTATION_SEG_AVG (8192, the generic cut's mean piece) so the
	 * fallback would very likely have cut a boundary inside it; the function-aware cut must still
	 * answer ONE unit, start to its own close, regardless of where kgenome_mutation_cut would fall.
	 */
	{
		static char big[20000];
		uint32_t i, at, close_at;
		struct kgenome_func_set fs2;

		at = (uint32_t)sprintf(big, "<?php\nfunction wide($a) {\n");
		for (i = 0; i < 700u; i++)
			at += (uint32_t)sprintf(big + at, "  $a = $a + %u;\n", i);
		at += (uint32_t)sprintf(big + at, "  return $a;\n");
		close_at = at;
		big[at++] = '}';
		big[at++] = '\n';
		memset(&fs2, 0, sizeof fs2);
		kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)big, at, &fs2);
		check(fs2.n == 1u && fs2.v[0].off == 6u && fs2.v[0].len == close_at + 1u - 6u,
		      "a function spanning several content-cut-sized windows is still ONE unit, start to its own close");
		check(fs2.n == 1u && fs2.v[0].len > KGENOME_MUTATION_SEG_AVG,
		      "sanity: the padded body really is bigger than what the generic cut would have pieced it into");
		kgenome_funcs_free(&fs2);
	}
}

/*
 * BLOCK NAMING for a script entry with no declared name (owner, 2026-11-06: "for the script
 * case, name a block with no function as block_<line_number>") - kof_func_name's new fallback,
 * sym_any.c. This is the engine-side mechanism alone: the two TOOL call sites that build the
 * throwaway KGENOME_FN_SCRIPT entry for a mutation cut's "remainder" piece (kv_mutation.c's
 * mtn_take_cb, kofexaminer_blocks.c's blk_unit) are kofexamine code, not linked into this binary
 * (mk/tools.mk builds them into kofexaminer/kofviewer only) - confirmed end to end instead with
 * `kofexaminer --blocks`, see STATUS.md's report of this merge.
 */
static void script_block_naming(void)
{
	/* ANONYMOUS CLOSURE: a real entry of the function table (kgenome_script_funcs_build), name_len
	 * 0 by construction (see tests/lib/genome/script_funcs.c's own anonymous_closure_has_no_name) -
	 * the owner's own words, "no function name", cover this case too, not only a remainder piece. */
	{
		static const char anon[] =
			"<?php\n"
			"$f = function ($a) {\n"
			"  return $a + 1;\n"
			"};\n";
		struct kgenome_func_set fs;
		char nm[32], fallback[32];

		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)anon, sizeof anon - 1u, &fs);
		check(fs.n == 1u && fs.v[0].name_len == 0u, "sanity: the closure is one entry, still anonymous");
		if (fs.n == 1u) {
			kof_fcn_name(fs.v[0].off, fallback, sizeof fallback);
			check(kof_func_name(&fs.v[0], NULL, 0, (const uint8_t *)anon, sizeof anon - 1u, nm, sizeof nm) == 0 &&
			      !strcmp(nm, "block_2"),
			      "an anonymous closure (one newline before its own \"function\") is block_2, the 1-based line it starts on");
			check(strcmp(nm, fallback) != 0,
			      "and never the binary's own fcn_<offset> - a script has no \"function\" word for a bare offset to imply");
		}
		kgenome_funcs_free(&fs);
	}

	/*
	 * A REMAINDER-STYLE ENTRY: no entry of any function table at all - exactly the throwaway
	 * KGENOME_FN_SCRIPT struct kv_mutation.c/kofexaminer_blocks.c build, off/len only, name_len 0 -
	 * for a piece kgenome_mutation_units' script_remainder() cut from the top-level code around real
	 * functions (never, itself, a function). Fixture matches the brief exactly: a top-level statement
	 * on line 1, another on line 5, blank lines between.
	 */
	{
		static const char rem[] =
			"<?php echo 1;\n"
			"\n"
			"\n"
			"\n"
			"echo 5;\n";
		const char *p1 = strstr(rem, "echo 1");
		const char *p5 = strstr(rem, "echo 5");
		struct kgenome_func blk;
		char nm[32];

		check(p1 != NULL && p5 != NULL, "sanity: both statements are found in the fixture");
		if (p1 && p5) {
			memset(&blk, 0, sizeof blk);
			blk.off = (uint64_t)(p1 - rem);
			blk.len = 6u;
			blk.kind = KGENOME_FN_SCRIPT;
			check(kof_func_name(&blk, NULL, 0, (const uint8_t *)rem, sizeof rem - 1u, nm, sizeof nm) == 0 &&
			      !strcmp(nm, "block_1"),
			      "a remainder piece on the file's own first line is block_1");

			memset(&blk, 0, sizeof blk);
			blk.off = (uint64_t)(p5 - rem);
			blk.len = 6u;
			blk.kind = KGENOME_FN_SCRIPT;
			check(kof_func_name(&blk, NULL, 0, (const uint8_t *)rem, sizeof rem - 1u, nm, sizeof nm) == 0 &&
			      !strcmp(nm, "block_5"),
			      "a remainder piece after 3 blank lines is block_5, matching the owner's own example");
		}
	}

	/* BOUNDARY: a unit AT offset 0 (no newline anywhere before it, the file's very first byte) is
	 * block_1, never block_0 - the convention is 1-based, matching the text pane's own gutter
	 * (kv_text.c: "ln + 1u" at the point it is drawn). */
	{
		static const char one[] = "<?php\necho 1;\n";
		struct kgenome_func blk;
		char nm[32];

		memset(&blk, 0, sizeof blk);
		blk.off = 0; blk.len = 5u; blk.kind = KGENOME_FN_SCRIPT;
		check(kof_func_name(&blk, NULL, 0, (const uint8_t *)one, sizeof one - 1u, nm, sizeof nm) == 0 &&
		      !strcmp(nm, "block_1"), "offset 0, no newline before it at all: block_1, not block_0");
	}

	/* HOSTILE: "\r\n" line endings are ONE line break, not two - the same reading the text pane's own
	 * line counter gives the same bytes (txt_line_count only ever tests for '\n', so a CRLF file's
	 * '\r' bytes are invisible to it, never counted as a break of their own; a lone '\r', old Mac
	 * text, is NOT recognised as a break either - this is not a new gap, the viewer already reads a
	 * CR-only file as one unbroken line). */
	{
		static const char crlf[] = "<?php\r\necho 1;\r\necho 2;\r\n";
		const char *p2 = strstr(crlf, "echo 2");
		struct kgenome_func blk;
		char nm[32];

		check(p2 != NULL, "sanity: the CRLF fixture's second statement is found");
		if (p2) {
			memset(&blk, 0, sizeof blk);
			blk.off = (uint64_t)(p2 - crlf);
			blk.len = 6u;
			blk.kind = KGENOME_FN_SCRIPT;
			check(kof_func_name(&blk, NULL, 0, (const uint8_t *)crlf, sizeof crlf - 1u, nm, sizeof nm) == 0 &&
			      !strcmp(nm, "block_3"),
			      "two CRLF line endings before it: block_3, a CRLF pair counted as ONE break");
		}
	}

	/*
	 * REGRESSION GUARD, the one that matters most: an ELF/PE entry (kind != KGENOME_FN_SCRIPT) with
	 * no symbol is UNCHANGED - still exactly fcn_<offset>, byte for byte, even with real `data`
	 * handed in (so the new branch could fire if the kind check were ever dropped or widened by
	 * accident; this is the test that would catch that).
	 */
	{
		static const uint8_t bin[32] = { 0 };
		struct kgenome_func f;
		char nm[32], want[32];

		memset(&f, 0, sizeof f);
		f.off = 0x1234u; f.len = 16u; f.kind = KGENOME_FN_FUNC; f.name_len = 0u;
		kof_fcn_name(f.off, want, sizeof want);
		check(kof_func_name(&f, NULL, 0, bin, sizeof bin, nm, sizeof nm) == 0 && !strcmp(nm, want),
		      "an ELF/PE function nothing names is still fcn_<offset>, unaffected by the script fallback");
	}

	/* A NAMED script function is unaffected: the name span branch returns before the new one is
	 * ever reached (name_len != 0 there is the gate on BOTH branches, see sym_any.c). */
	{
		static const char named[] = "<?php\nfunction helper_decode($a) { return $a; }\n";
		struct kgenome_func_set fs;
		char nm[32];

		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)named, sizeof named - 1u, &fs);
		check(fs.n == 1u && fs.v[0].name_len != 0u, "sanity: the function has a declared name");
		if (fs.n == 1u)
			check(kof_func_name(&fs.v[0], NULL, 0, (const uint8_t *)named, sizeof named - 1u, nm, sizeof nm) == 1 &&
			      !strcmp(nm, "helper_decode"),
			      "a script function WITH a real name keeps showing it, never block_<line>");
		kgenome_funcs_free(&fs);
	}
}

/*
 * EVAL()-LITERAL ISLANDS, end to end through kgenome_mutation_units (owner, 2026-11-10): a script
 * loads code from a string via eval() - a call the language's own nucleo vocabulary
 * (KGENOME_NUCLEO_EVAL, nucleo.h) names - and, when the argument is a bare, non-interpolating,
 * escape-free literal, kgenome_script_funcs_build now follows it as a further PHP fragment
 * (script_funcs.c's own "EVAL()-LITERAL ISLANDS" header). A function declared INSIDE the eval'd
 * string gets its own real mutation unit here, exactly like a top-level one - not an opaque blob
 * of STRING data, which is what it was before this feature and still is for every shape this
 * feature does not recognise (a variable, a concatenation, a decode call, an escaped or
 * interpolating string).
 */
static void eval_island_functions(void)
{
	static const char php[] =
		"<?php\n"
		"eval('function helper(){ system($_GET[\"c\"]); } helper(); ');\n"
		"$z = 1;\n";
	struct kgenome_func_set fs;
	struct kof_range ext = { 0, (uint64_t)(sizeof php - 1u) };
	struct sfn_got g;
	const char *helper_at = strstr(php, "function helper");

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	check(fs.n == 1u, "the function declared inside the eval()'d literal is found, not left opaque");
	if (fs.n == 1u && helper_at) {
		char nm[32];
		uint64_t helper_off = (uint64_t)(helper_at - php);

		check(fs.v[0].off == helper_off,
		      "its span starts exactly where the declaration starts, inside the string's own bytes");
		check((fs.v[0].flags & KGENOME_FN_F_EVAL_ISLAND) != 0,
		      "flagged as found inside an eval()-literal island, not a top-level declaration");
		check(kof_func_name(&fs.v[0], NULL, 0, (const uint8_t *)php, sizeof php - 1u, nm, sizeof nm) == 1 &&
		      !strcmp(nm, "helper"), "its own declared name, the same display path as a top-level function");
		check((fs.partial & KGENOME_FNTAB_P_EVAL_SKIP) == 0, "a clean merge is not reported as a skip");
	}

	/* THE SAME TABLE THROUGH kgenome_mutation_units: the function gets its own exact unit, and the
	 * eval() call's own quotes/parens/semicolon and the top-level code around it still get the
	 * ordinary content-defined remainder cut - nothing around it goes missing (fn_in/script_
	 * remainder, unchanged by this feature: they only ever read kgenome_func_set's final list). */
	memset(&g, 0, sizeof g);
	kgenome_mutation_units(&(const struct kgenome_mutation_req){
			.p = (const uint8_t *)php, .n_obj = sizeof php - 1u,
			.format = KOF_FMT_SCRIPT, .mask = KOF_SCAN_ALL,
			.ext = &ext, .n_ext = 1, .funcs = &fs, .fn = sfn_take, .user = &g,
		});
	{
		uint32_t i, n_fn = 0;
		int helper_seen = 0;
		uint64_t covered = 0;

		for (i = 0; i < g.n; i++) {
			covered += g.len[i];
			if (g.kind[i] != KGENOME_FN_SCRIPT)
				continue;
			n_fn++;
			if (fs.n == 1u && g.off[i] == fs.v[0].off && g.len[i] == fs.v[0].len)
				helper_seen = 1;
		}
		check(n_fn == 1u, "exactly one function unit, found inside the eval()'d literal");
		check(helper_seen, "its unit is the declaration's own exact span");
		check(g.n > n_fn,
		      "the eval() call's own bytes and the top-level code around it still get remainder units");
		check(covered == sizeof php - 1u,
		      "every byte of the object is covered exactly once: no gap, no overlap, the quote bytes included");
	}
	kgenome_funcs_free(&fs);

	/* A LITERAL WITH NO FUNCTION INSIDE IT: still merged cleanly (no phantom unit, no skip), and
	 * still fully covered by the ordinary remainder cut - never invisible, the owner's own stated
	 * concern for a script that "loads code from a string" with no function in it. */
	{
		static const char noop[] = "<?php\neval('echo 1; ');\n";

		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)noop, sizeof noop - 1u, &fs);
		check(fs.n == 0u && (fs.partial & KGENOME_FNTAB_P_EVAL_SKIP) == 0,
		      "no function inside: an empty table, not a skip - the merge itself succeeded");
		kgenome_funcs_free(&fs);
	}
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
	script_functions();
	script_block_naming();
	eval_island_functions();
	if (failures) {
		printf("mutation units: %d failure(s)\n", failures);
		return 1;
	}
	printf("mutation units: one function unit per function, byte pieces tile "
	       "and split at the library, a PE's functions from .pdata - ok\n");
	return 0;
}
