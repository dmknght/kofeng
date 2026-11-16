/*
 * fntab_meta.c - the function table made from LOADER / ABI METADATA ONLY (owner 2026-11-16; design /mnt/games/normtest/design_partition_meta.md).
 *
 * Every row builds its object from bytes (no sample is embedded): an ELF with a section table or without, one R X segment, and the tables a row needs - .init_array,
 * .ARM.exidx (section or PT_ARM_EXIDX), .gopclntab (Go 1.2 and 1.20 headers), or nothing at all; a PE x64 whose .pdata holds a chained part far from its function.
 * RED on the code before the change (2026-11-16): the start-only tables and the Go table were not read (their starts missing, or found only when a decoded call named
 * them), an object with no metadata was cut at the call targets the walk decoded, and a chained part far from its function was dropped from the table.
 *
 * Held:
 *   INITARR   every pointer of .init_array / .fini_array is a declared start (source INITARR) of the NONE unit (round 4); a zero and an all-ones slot and a pointer into data are counted, not followed;
 *             with no section table, the arrays named by PT_DYNAMIC are read
 *   EXIDX     every row's prel31 is a start (source EXIDX), Thumb bit taken off into isa_mode; a row with bit 31 set is counted; PT_ARM_EXIDX with no section table
 *   GOPCLN    Go 1.20 and Go 1.2 tables: start AND end of every row (end_source PCTAB, trust HIGH); a row that does not rise is counted; a header that lies is refused
 *   NO_META   an object with no metadata (its code calls itself, the old walk split it) is ONE entry of trust NONE per code extent, case NO_META, P_NO_META, state PARTIAL;
 *             the entry point alone does not split it
 *   ENTRY     beside any other source the entry point is a start (source ENTRY)
 *   TRUST     a symbol with a size is HIGH, a symbol of size 0 a declared start (round 4)
 *   PARTS     a chained .pdata part far from its root is a RANGE of the root (kgenome_funcs_n_ranges 2, kgenome_funcs_at answers the root), not a function and not dropped
 *   NO_DECODE the table of a stripped object is the same whatever its code bytes are (nothing decodes them)
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/fntab.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/pe_image.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_private.h>
#include "fntab_pe_kit.h"

#define TEXT 0x100u
#define BASE 0x400000u

/* ---- a small ELF writer: one R X segment over the whole file up to the section table ---- */

struct xsec { const char *name; uint32_t type; uint64_t flags; const uint8_t *data; uint32_t n; uint32_t off; };
struct xseg { uint32_t type; int sec; };        /* a segment over extra section `sec` */

struct eo {
	int c64, be, sections;
	uint16_t em;
	const uint8_t *text;
	uint32_t text_n;
	struct xsec x[4];
	unsigned nx;
	struct xseg g[2];
	unsigned ng;
	const struct sym1 { const char *name; uint64_t value, size; uint8_t info; } *sym;
	unsigned nsym;
};

static uint8_t EB[0x8000];

static void e16(const struct eo *e, uint32_t at, uint32_t v) { EB[at + (e->be ? 1u : 0u)] = (uint8_t)v; EB[at + (e->be ? 0u : 1u)] = (uint8_t)(v >> 8); }
static void e32(const struct eo *e, uint32_t at, uint32_t v) { int i; for (i = 0; i < 4; i++) EB[at + (uint32_t)(e->be ? 3 - i : i)] = (uint8_t)(v >> (8 * i)); }
static void e64(const struct eo *e, uint32_t at, uint64_t v) { int i; for (i = 0; i < 8; i++) EB[at + (uint32_t)(e->be ? 7 - i : i)] = (uint8_t)(v >> (8 * i)); }
static void ew(const struct eo *e, uint32_t at, uint64_t v) { if (e->c64) e64(e, at, v); else e32(e, at, (uint32_t)v); }

/* The extra sections are laid out behind .text, 8-aligned; this answers their file offsets (and so their addresses: BASE + offset) before the data is written. */
static void lay_x(struct eo *e)
{
	uint32_t at = (TEXT + e->text_n + 7u) & ~7u;
	unsigned k;

	for (k = 0; k < e->nx; k++) {
		e->x[k].off = at;
		at = (at + e->x[k].n + 7u) & ~7u;
	}
}

static uint32_t elf_make(struct eo *e)
{
	const int c = e->c64;
	const uint32_t ehsz = c ? 64u : 52u, phsz = c ? 56u : 32u, shsz = c ? 64u : 40u, symsz = c ? 24u : 16u;
	const uint32_t phn = 1u + e->ng;
	uint32_t seg_end, n, k, ph = ehsz;
	char shstr[256];
	uint32_t shstr_n = 1, nm[8], sh, shn = 0, symoff = 0, stroff = 0, strn = 1;

	memset(EB, 0, sizeof EB);
	lay_x(e);
	seg_end = e->nx ? e->x[e->nx - 1u].off + e->x[e->nx - 1u].n : TEXT + e->text_n;
	EB[0] = 0x7f; EB[1] = 'E'; EB[2] = 'L'; EB[3] = 'F'; EB[4] = c ? 2 : 1; EB[5] = e->be ? 2 : 1; EB[6] = 1;
	e16(e, 16, 2); e16(e, 18, e->em); e32(e, 20, 1);
	ew(e, 24, BASE + TEXT);
	ew(e, 28 + (c ? 4u : 0u), ph);
	e16(e, c ? 52 : 40, ehsz); e16(e, c ? 54 : 42, phsz); e16(e, c ? 56 : 44, phn);
	if (c) {
		e32(e, ph, 1); e32(e, ph + 4, 5); e64(e, ph + 16, BASE); e64(e, ph + 24, BASE); e64(e, ph + 32, seg_end); e64(e, ph + 40, seg_end); e64(e, ph + 48, 0x1000);
	} else {
		e32(e, ph, 1); e32(e, ph + 8, BASE); e32(e, ph + 12, BASE); e32(e, ph + 16, seg_end); e32(e, ph + 20, seg_end); e32(e, ph + 24, 5); e32(e, ph + 28, 0x1000);
	}
	for (k = 0; k < e->ng; k++) {
		const uint32_t p = ph + (k + 1u) * phsz;
		const struct xsec *s = &e->x[e->g[k].sec];

		if (c) {
			e32(e, p, e->g[k].type); e32(e, p + 4, 4); e64(e, p + 8, s->off); e64(e, p + 16, BASE + s->off); e64(e, p + 24, BASE + s->off);
			e64(e, p + 32, s->n); e64(e, p + 40, s->n); e64(e, p + 48, 4);
		} else {
			e32(e, p, e->g[k].type); e32(e, p + 4, s->off); e32(e, p + 8, BASE + s->off); e32(e, p + 12, BASE + s->off);
			e32(e, p + 16, s->n); e32(e, p + 20, s->n); e32(e, p + 24, 4); e32(e, p + 28, 4);
		}
	}
	memcpy(EB + TEXT, e->text, e->text_n);
	for (k = 0; k < e->nx; k++)
		memcpy(EB + e->x[k].off, e->x[k].data, e->x[k].n);
	n = seg_end;
	if (!e->sections)
		return n;
	/* the symbol table (when asked) and .strtab */
	if (e->nsym) {
		symoff = (n + 7u) & ~7u;
		stroff = symoff + (e->nsym + 1u) * symsz;
		for (k = 0; k < e->nsym; k++) {
			const uint32_t o = symoff + (k + 1u) * symsz;
			const size_t ln = strlen(e->sym[k].name) + 1u;

			memcpy(EB + stroff + strn, e->sym[k].name, ln);
			e32(e, o, strn);
			if (c) {
				EB[o + 4] = e->sym[k].info; e16(e, o + 6, 1); e64(e, o + 8, e->sym[k].value); e64(e, o + 16, e->sym[k].size);
			} else {
				e32(e, o + 4, (uint32_t)e->sym[k].value); e32(e, o + 8, (uint32_t)e->sym[k].size); EB[o + 12] = e->sym[k].info; e16(e, o + 14, 1);
			}
			strn += (uint32_t)ln;
		}
		n = stroff + strn;
	}
	shstr[0] = 0;
#define NAME(i, s) do { nm[i] = shstr_n; memcpy(shstr + shstr_n, s, strlen(s) + 1u); shstr_n += (uint32_t)strlen(s) + 1u; } while (0)
	NAME(0, ".text");
	for (k = 0; k < e->nx; k++)
		NAME(1u + k, e->x[k].name);
	NAME(5, ".shstrtab");
	NAME(6, ".symtab");
	NAME(7, ".strtab");
#undef NAME
	memcpy(EB + n, shstr, shstr_n);
	{
		const uint32_t shstr_off = n;

		sh = (n + shstr_n + 7u) & ~7u;
#define SEC(name, type, flags, addr, off, size, link, entsz) do { const uint32_t o_ = sh + shn * shsz; \
	e32(e, o_, name); e32(e, o_ + 4, type); \
	if (c) { e64(e, o_ + 8, flags); e64(e, o_ + 16, addr); e64(e, o_ + 24, off); e64(e, o_ + 32, size); e32(e, o_ + 40, link); e64(e, o_ + 56, entsz); } \
	else { e32(e, o_ + 8, (uint32_t)(flags)); e32(e, o_ + 12, (uint32_t)(addr)); e32(e, o_ + 16, off); e32(e, o_ + 20, size); e32(e, o_ + 24, link); e32(e, o_ + 36, entsz); } \
	shn++; } while (0)
		SEC(0, 0, 0, 0, 0, 0, 0, 0);
		SEC(nm[0], 1, 6, BASE + TEXT, TEXT, e->text_n, 0, 0);
		for (k = 0; k < e->nx; k++)
			SEC(nm[1 + k], e->x[k].type, e->x[k].flags, BASE + e->x[k].off, e->x[k].off, e->x[k].n, 0, 0);
		if (e->nsym) {
			SEC(nm[6], 2, 0, 0, symoff, (e->nsym + 1u) * symsz, shn + 1u, symsz);
			SEC(nm[7], 3, 0, 0, stroff, strn, 0, 0);
		}
		SEC(nm[5], 3, 0, 0, shstr_off, shstr_n, 0, 0);
#undef SEC
	}
	if (c) { e64(e, 40, sh); e16(e, 58, shsz); e16(e, 60, shn); e16(e, 62, shn - 1u); }
	else { e32(e, 32, sh); e16(e, 46, shsz); e16(e, 48, shn); e16(e, 50, shn - 1u); }
	return sh + shn * shsz;
}


/* The entries a metadata source declared (round 2: the code no metadata declares is an entry of trust NONE as well). */
static __attribute__((unused)) uint32_t n_decl(const struct kgenome_func_set *s)
{
	uint32_t i, k = 0;

	for (i = 0; i < s->n; i++)
		k += s->v[i].trust != KGENOME_FN_TRUST_NONE;
	return k;
}

/* The entries of trust HIGH (a declared extent); since phase 2 the code no metadata declares may hold DERIVED entries beside the NONE ones. */
static uint32_t n_high(const struct kgenome_func_set *s)
{
	uint32_t i, k = 0;

	for (i = 0; i < s->n; i++)
		k += s->v[i].trust == KGENOME_FN_TRUST_HIGH;
	return k;
}

/* A DERIVED entry at `off` of `len` bytes whose source holds `src` (phase 2). */
static int dfn(const struct kgenome_func_set *s, uint64_t off, uint64_t len, uint16_t src)
{
	const uint32_t i = kgenome_funcs_start(s, off);

	return i != KGENOME_FUNCS_NONE && s->v[i].trust == KGENOME_FN_TRUST_DERIVED && s->v[i].len == len && (s->v[i].source & src) == src;
}

/* The declared start at `off` (round 4), or a zero one (source 0) when there is none. */
static const struct kgenome_func_start g_nostart;

static const struct kgenome_func_start *sat(const struct kgenome_func_set *s, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < s->n_st; i++)
		if (s->st[i].off == off)
			return &s->st[i];
	return &g_nostart;
}

struct et { struct kgenome_elf_info ei; struct kgenome_obj o; struct kgenome_func_set fs; int ok; };

static void etab(uint32_t n, struct et *t)
{
	memset(t, 0, sizeof *t);
	t->ok = kgenome_elf_image_parse(kof_buf_make(EB, n), &t->ei, &t->o);
	t->o.file_header = &t->ei;
	if (t->ok)
		kgenome_diag_funcs_with_walk(&t->o, EB, n, NULL, &t->fs);
}

static const struct kgenome_func *fat(const struct kgenome_func_set *s, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < s->n; i++)
		if (s->v[i].off == off)
			return &s->v[i];
	return NULL;
}

/* x86-64 code that calls itself: S at 0 calls A (0x20) and B (0x40); the old walk made three functions of it. int3 between. */
static uint32_t calls_text(uint8_t *t)
{
	int32_t d;

	memset(t, 0xcc, 0x60);
	t[0] = 0xe8; d = 0x20 - 5; memcpy(t + 1, &d, 4);
	t[5] = 0xe8; d = 0x40 - 10; memcpy(t + 6, &d, 4);
	t[10] = 0xc3;
	memcpy(t + 0x20, "\x55\x48\x89\xe5\x5d\xc3", 6);
	memcpy(t + 0x40, "\x55\x48\x89\xe5\x5d\xc3", 6);
	return 0x60;
}

static void t_nometa(void)
{
	uint8_t text[0x60];
	struct eo e;
	struct et t;
	int sect;

	for (sect = 0; sect < 2; sect++) {
		memset(&e, 0, sizeof e);
		e.c64 = 1; e.em = 62; e.sections = sect;
		e.text = text; e.text_n = calls_text(text);
		etab(elf_make(&e), &t);
		CK(t.ok);
		/* phase 2 (2026-11-16): no metadata, but the entry is a declared start: the descent from it derives S and the two functions S calls; the rest is NONE */
		CK(n_high(&t.fs) == 0u && dfn(&t.fs, TEXT, 11, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED));
		CK(dfn(&t.fs, TEXT + 0x20, 6, KGENOME_FN_S_DERIVED_CALL) && dfn(&t.fs, TEXT + 0x40, 6, KGENOME_FN_S_DERIVED_CALL));
		CK(t.fs.ccase == KGENOME_FNTAB_C_NO_META && (t.fs.partial & KGENOME_FNTAB_P_NO_META) && t.fs.state == KGENOME_FNTAB_PARTIAL);
		/* one extent: .text with a section table; without one the executable segment less the ELF and program headers (round 3, PMA-2: not from the entry) */
		CK(t.fs.n && t.fs.v[0].off == (sect ? TEXT : 64u + 56u) && t.fs.v[t.fs.n - 1u].off + t.fs.v[t.fs.n - 1u].len == TEXT + 0x60u);
		CK(t.fs.n == (sect ? 6u : 7u) && t.fs.n_undeclared == (sect ? 3u : 4u));      /* the int3 runs behind S, A and B (and the headers' tail) stay NONE */
		CK(t.fs.n_st == 1u && sat(&t.fs, TEXT)->source == KGENOME_FN_S_ENTRY);   /* round 4: the entry is a declared start even with nothing else */
		CK(kgenome_funcs_at(&t.fs, TEXT + 0x41) == kgenome_funcs_start(&t.fs, TEXT + 0x40));
		kgenome_funcs_free(&t.fs);
	}
	/* NO_DECODE: other code bytes, the same table */
	memset(text, 0x90, sizeof text);
	memset(&e, 0, sizeof e);
	e.c64 = 1; e.em = 62; e.sections = 1; e.text = text; e.text_n = 0x60;
	etab(elf_make(&e), &t);
	/* phase 2: nops to the end of .text: one function from the entry, whose path ran out of the code (INCOMPLETE) */
	CK(t.ok && t.fs.n == 1 && t.fs.v[0].off == TEXT && t.fs.v[0].len == 0x60u && t.fs.v[0].trust == KGENOME_FN_TRUST_DERIVED &&
	   t.fs.v[0].flags == KGENOME_FN_F_INCOMPLETE);
	kgenome_funcs_free(&t.fs);
}

static void t_initarr(void)
{
	uint8_t text[0x60], arr[40], fin[8];
	struct eo e;
	struct et t;

	int sect;

	for (sect = 1; sect >= 0; sect--) {
		memset(&e, 0, sizeof e);
		e.c64 = 1; e.em = 62; e.sections = sect;
		e.text = text; e.text_n = calls_text(text);
		memset(arr, 0, sizeof arr);
		memset(fin, 0, sizeof fin);
		/* .init_array: A, a zero slot (a PIE's relocated slot), B, all-ones, a pointer into the array itself (data) */
		e.x[0] = (struct xsec){ ".init_array", 14, 3, arr, sizeof arr, 0 };
		e.x[1] = (struct xsec){ ".fini_array", 15, 3, fin, sizeof fin, 0 };
		e.nx = 2;
		lay_x(&e);
		memcpy(arr + 0, &(uint64_t){ BASE + TEXT + 0x20 }, 8);
		memcpy(arr + 16, &(uint64_t){ BASE + TEXT + 0x40 }, 8);
		memcpy(arr + 24, &(uint64_t){ UINT64_MAX }, 8);
		memcpy(arr + 32, &(uint64_t){ BASE + 0x7000u }, 8);               /* an address in no segment */
		memcpy(fin, &(uint64_t){ BASE + TEXT + 0x50 }, 8);
		if (!sect) {
			/* no section table: PT_DYNAMIC names the arrays (DT_INIT_ARRAY 25 / SZ 27, DT_FINI_ARRAY 26 / SZ 28, DT_NULL) */
			static uint64_t dyn[10];

			dyn[0] = 25; dyn[1] = BASE + e.x[0].off; dyn[2] = 27; dyn[3] = sizeof arr;
			dyn[4] = 26; dyn[5] = BASE + e.x[1].off; dyn[6] = 28; dyn[7] = sizeof fin; dyn[8] = 0; dyn[9] = 0;
			e.x[2] = (struct xsec){ ".dynamic", 6, 3, (const uint8_t *)dyn, sizeof dyn, 0 };
			e.nx = 3;
			e.g[0] = (struct xseg){ 2, 2 };
			e.ng = 1;
		}
		etab(elf_make(&e), &t);
		CK(t.ok);
		CK(t.fs.ccase == KGENOME_FNTAB_C_ELF_META && !(t.fs.partial & KGENOME_FNTAB_P_NO_META));
		/* round 4: every pointer is a declared START in the one NONE unit, which is not cut (the rule changed: they were MEDIUM units to the next start) */
		CK((sat(&t.fs, TEXT + 0x20)->source & KGENOME_FN_S_INITARR));
		CK((sat(&t.fs, TEXT + 0x40)->source & KGENOME_FN_S_INITARR));
		CK((sat(&t.fs, TEXT + 0x50)->source & KGENOME_FN_S_INITARR));     /* .fini_array */
		CK(sat(&t.fs, TEXT)->source == KGENOME_FN_S_ENTRY);                      /* the entry point is a declared start too */
		/* phase 2: no extent is declared (no HIGH unit); the declared starts derive their functions: the entry S, A and B (init), 0x50 (fini: int3 to the end) */
		CK(n_high(&t.fs) == 0u && t.fs.n_st == 4u && dfn(&t.fs, TEXT + 0x20, 6, KGENOME_FN_S_INITARR | KGENOME_FN_S_DERIVED_SEED | KGENOME_FN_S_DERIVED_CALL));
		CK(dfn(&t.fs, TEXT, 11, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED) && dfn(&t.fs, TEXT + 0x50, sect ? 0x10u : kgenome_funcs_range(&t.fs, kgenome_funcs_start(&t.fs, TEXT + 0x50), 0).len, KGENOME_FN_S_INITARR | KGENOME_FN_S_DERIVED_SEED));
		/* int3 is no exit (cfg_isa.c): 0x50 runs out of the code (.text, or with no section table the segment) */
		CK(kgenome_funcs_start(&t.fs, TEXT + 0x50) != KGENOME_FUNCS_NONE && t.fs.v[kgenome_funcs_start(&t.fs, TEXT + 0x50)].flags == (sect ? KGENOME_FN_F_INCOMPLETE : KGENOME_FN_F_BROKEN));   /* with no section table the path runs on into the arrays' bytes and stops at one that decodes as nothing */
		{
			struct kgenome_fntab_list l;

			memset(&l, 0, sizeof l);
			kgenome_fntab_initarr(kof_buf_make(EB, sizeof EB), &t.ei, &l);
			CK(l.n == 3u && l.n_bad == 3u);             /* zero, all-ones, data */
			kgenome_fntab_list_free(&l);
		}
		kgenome_funcs_free(&t.fs);
	}
}

static void t_exidx(void)
{
	uint8_t text[0x80], tab[32];
	struct eo e;
	struct et t;

	int sect;

	memset(text, 0, sizeof text);
	for (sect = 1; sect >= 0; sect--) {
		uint32_t row;

		memset(&e, 0, sizeof e);
		e.c64 = 0; e.em = 40; e.sections = sect;
		e.text = text; e.text_n = sizeof text;
		e.x[0] = (struct xsec){ ".ARM.exidx", 0x70000001u, 0x82, tab, sizeof tab, 0 };
		e.nx = 1;
		lay_x(&e);
		memset(tab, 0, sizeof tab);
		/* row 0 -> .text + 0x00, row 1 -> .text + 0x41 (Thumb), row 2 bit 31 set (refused), row 3 -> .text + 0x60 */
		for (row = 0; row < 4; row++) {
			const uint64_t va = BASE + e.x[0].off + 8u * row;
			const uint64_t to = BASE + TEXT + (row == 0 ? 0u : row == 1 ? 0x41u : 0x60u);
			const uint32_t w0 = row == 2 ? 0x80000000u : (uint32_t)((to - va) & 0x7fffffffu);

			memcpy(tab + 8u * row, &w0, 4);
			memcpy(tab + 8u * row + 4u, &(uint32_t){ 1u }, 4);
		}
		if (!sect) {
			e.g[0] = (struct xseg){ 0x70000001u, 0 };       /* PT_ARM_EXIDX */
			e.ng = 1;
		}
		etab(elf_make(&e), &t);
		CK(t.ok && t.fs.ccase == KGENOME_FNTAB_C_ELF_META);
		/* round 4: the rows are declared starts (a leaf has no row by definition), not units (the rule changed: they were MEDIUM units to the next row) */
		CK((sat(&t.fs, TEXT)->source & KGENOME_FN_S_EXIDX) && (sat(&t.fs, TEXT)->source & KGENOME_FN_S_ENTRY));
		CK(sat(&t.fs, TEXT + 0x40)->source == KGENOME_FN_S_EXIDX && sat(&t.fs, TEXT + 0x40)->isa_mode == KGENOME_FN_ISA_THUMB);
		CK(sat(&t.fs, TEXT + 0x60)->source != 0);
		/* phase 2: ARM `andeq r0, r0, r0` (zeros) to the end from 0x00 and 0x60: derived, ran out of the code; the Thumb row is skipped (one ISA a space) */
		/* 2026-11-17: the row at 0x60 is run into by the `andeq` before it (no call, no jump): an unwind row there declares no entry (fntab_derive.c is_entry),
		 * so the entry's function runs on to the end of .text, or of the segment (the table's own bytes). It was a function of its own: RED before the rule. */
		CK(n_high(&t.fs) == 0u && t.fs.n_st == 3u && t.fs.n_derive_skipped == 1u && kgenome_funcs_start(&t.fs, TEXT + 0x60) == KGENOME_FUNCS_NONE);
		CK(dfn(&t.fs, TEXT, sect ? 0x80u : 0xa0u, KGENOME_FN_S_EXIDX | KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED));   /* the Thumb row at 0x41 is no seed */
		{
			struct kgenome_fntab_list l;

			memset(&l, 0, sizeof l);
			kgenome_fntab_exidx(kof_buf_make(EB, sizeof EB), &t.ei, &l);
			CK(l.n == 3u && l.n_bad == 1u);
			kgenome_fntab_list_free(&l);
		}
		kgenome_funcs_free(&t.fs);
	}
	/* not ARM: the strategy reads nothing */
	{
		struct kgenome_fntab_list l;

		e.em = 62;
		etab(elf_make(&e), &t);
		memset(&l, 0, sizeof l);
		kgenome_fntab_exidx(kof_buf_make(EB, sizeof EB), &t.ei, &l);
		CK(l.n == 0u && l.n_bad == 0u);
		kgenome_fntab_list_free(&l);
		kgenome_funcs_free(&t.fs);
	}
}

/*
 * AN UNWIND ROW INSIDE A FUNCTION (2026-11-17, ARM stripped twins: uClibc's syscall wrappers carry .ARM.exidx rows at `close+0x2c` and `close+0x3c`). A row
 * that the code before it runs into, or that a branch from BELOW it targets, is no entry: it is the body of the function that reaches it. A row a branch
 * from ABOVE targets (the function's own loop back to its start) stays an entry. RED on the old code: each row cut its function in two (R1).
 *   A: 0x00 mov r0,#1; 0x04 mov r1,#2; 0x08 add r0,r0,r1 (row); 0x0c bx lr                       -> one function 0x00..0x10
 *   B: 0x00 cmp r0,#0; 0x04 bne 0x10; 0x08 bx lr; 0x0c mov r0,#5 (no path reads it); 0x10 mov r0,#0 (row); 0x14 bx lr -> one function, ranges
 *      0x00..0x0c and 0x10..0x18 (a zero word there would be padding to the walk, and the hole the body's)
 *   C: 0x00 bx lr; 0x04 (row) subs r0,r0,#1; 0x08 beq 0x10; 0x0c b 0x04; 0x10 bx lr           -> the loop head (a branch from ABOVE) stays a start
 *   D: case A with a size-0 FUNC symbol at the row 0x08 too                                        -> a symbol declares an entry: two functions
 */
static void t_exidx_inside(void)
{
	static const uint32_t ca[] = { 0xe3a00001u, 0xe3a01002u, 0xe0800001u, 0xe12fff1eu };
	static const uint32_t cb[] = { 0xe3500000u, 0x1a000001u, 0xe12fff1eu, 0xe3a00005u, 0xe3a00000u, 0xe12fff1eu };
	static const uint32_t cc[] = { 0xe12fff1eu, 0xe2500001u, 0x0a000000u, 0xeafffffcu, 0xe12fff1eu };
	static const struct { const uint32_t *w; unsigned n; uint32_t row1; } k[] = { { ca, 4, 0x08 }, { cb, 6, 0x10 }, { cc, 5, 0x04 }, { ca, 4, 0x08 } };
	static const struct sym1 sd[1] = { { "d", BASE + TEXT + 0x08, 0, 0x12 } };
	uint8_t text[0x20], tab[16];
	unsigned c;

	printf("exidx rows inside a function\n");
	for (c = 0; c < 4u; c++) {
		struct eo e;
		struct et t;
		uint32_t row, i;

		memset(text, 0, sizeof text);
		memcpy(text, k[c].w, k[c].n * 4u);
		memset(&e, 0, sizeof e);
		e.c64 = 0; e.em = 40; e.sections = 1;
		e.text = text; e.text_n = k[c].n * 4u;
		e.x[0] = (struct xsec){ ".ARM.exidx", 0x70000001u, 0x82, tab, sizeof tab, 0 };
		e.nx = 1;
		if (c == 3) {
			e.sym = sd;
			e.nsym = 1;
		}
		lay_x(&e);
		memset(tab, 0, sizeof tab);
		for (row = 0; row < 2u; row++) {
			const uint64_t va = BASE + e.x[0].off + 8u * row;
			const uint64_t to = BASE + TEXT + (row ? k[c].row1 : 0u);
			const uint32_t w0 = (uint32_t)((to - va) & 0x7fffffffu);

			memcpy(tab + 8u * row, &w0, 4);
			memcpy(tab + 8u * row + 4u, &(uint32_t){ 1u }, 4);
		}
		etab(elf_make(&e), &t);
		CK(t.ok);
		i = kgenome_funcs_start(&t.fs, TEXT);
		CK(i != KGENOME_FUNCS_NONE && t.fs.v[i].trust == KGENOME_FN_TRUST_DERIVED);
		if (c == 0)
			CK(dfn(&t.fs, TEXT, 0x10, KGENOME_FN_S_DERIVED_SEED) && kgenome_funcs_start(&t.fs, TEXT + 0x08) == KGENOME_FUNCS_NONE);
		if (c == 1) {
			CK(dfn(&t.fs, TEXT, 0x0c, KGENOME_FN_S_DERIVED_SEED) && kgenome_funcs_start(&t.fs, TEXT + 0x10) == KGENOME_FUNCS_NONE);
			CK(i != KGENOME_FUNCS_NONE && kgenome_funcs_at(&t.fs, TEXT + 0x10) == i && kgenome_funcs_at(&t.fs, TEXT + 0x14) == i);
		}
		if (c == 2)
			CK(dfn(&t.fs, TEXT, 0x04, KGENOME_FN_S_DERIVED_SEED) && dfn(&t.fs, TEXT + 0x04, 0x10, KGENOME_FN_S_EXIDX | KGENOME_FN_S_DERIVED_SEED));
		if (c == 3)
			CK(dfn(&t.fs, TEXT, 0x08, KGENOME_FN_S_DERIVED_SEED) && dfn(&t.fs, TEXT + 0x08, 0x08, KGENOME_FN_S_EXIDX | KGENOME_FN_S_DERIVED_SEED));
		kgenome_funcs_free(&t.fs);
	}
}

/* .gopclntab: Go 1.20 (0xfffffff1, entryoff u32 relative to textStart) or Go 1.2 (0xfffffffb, addresses). Rows at 0x00, 0x30 and a final entry at 0x60. */
static uint32_t go_tab(uint8_t *g, uint32_t magic, int rising, uint64_t nfunc)
{
	memset(g, 0, 128);
	memcpy(g, &magic, 4);
	g[6] = 1; g[7] = 8;
	memcpy(g + 8, &nfunc, 8);
	if (magic == 0xfffffff1u) {
		const uint64_t text = BASE + TEXT, rows = 72;
		uint32_t r[5] = { 0, 0x100, rising ? 0x30u : 0x00u, 0x200, 0x60 };

		memcpy(g + 8 + 2 * 8, &text, 8);
		memcpy(g + 8 + 7 * 8, &rows, 8);
		memcpy(g + rows, r, sizeof r);
		return (uint32_t)rows + (uint32_t)sizeof r;
	} else {
		uint64_t r[5] = { BASE + TEXT, 0x100, BASE + TEXT + (rising ? 0x30u : 0u), 0x200, BASE + TEXT + 0x60 };

		memcpy(g + 16, r, sizeof r);
		return 16u + (uint32_t)sizeof r;
	}
}

static void t_gopcln(void)
{
	uint8_t text[0x60], g[128];
	struct eo e;
	struct et t;
	const struct kgenome_func *f;
	const uint32_t magics[2] = { 0xfffffff1u, 0xfffffffbu };
	unsigned m;

	for (m = 0; m < 2; m++) {
		memset(&e, 0, sizeof e);
		e.c64 = 1; e.em = 62; e.sections = 1;
		e.text = text; e.text_n = calls_text(text);
		e.x[0] = (struct xsec){ ".gopclntab", 1, 2, g, go_tab(g, magics[m], 1, 2), 0 };
		e.nx = 1;
		etab(elf_make(&e), &t);
		CK(t.ok && t.fs.ccase == KGENOME_FNTAB_C_ELF_GO);
		f = fat(&t.fs, TEXT);
		CK(f && (f->source & KGENOME_FN_S_GOPCLN) && f->len == 0x30u && f->end_source == KGENOME_FN_E_PCTAB && f->trust == KGENOME_FN_TRUST_HIGH);
		f = fat(&t.fs, TEXT + 0x30);
		CK(f && f->source == KGENOME_FN_S_GOPCLN && f->len == 0x30u && f->trust == KGENOME_FN_TRUST_HIGH && !(f->flags & KGENOME_FN_F_END_OPEN));
		CK(t.fs.n == 2u && !fat(&t.fs, TEXT + 0x20) && !fat(&t.fs, TEXT + 0x40));
		kgenome_funcs_free(&t.fs);
		/* a row that does not rise: counted, the next row is read against the last accepted entry (one function 0x00..0x60) */
		e.x[0].n = go_tab(g, magics[m], 0, 2);
		etab(elf_make(&e), &t);
		{
			struct kgenome_fntab_list l;

			memset(&l, 0, sizeof l);
			kgenome_fntab_gopcln(kof_buf_make(EB, sizeof EB), &t.ei, &l);
			CK(l.n == 1u && l.n_bad == 1u && l.v[0].len == 0x60u);
			kgenome_fntab_list_free(&l);
		}
		kgenome_funcs_free(&t.fs);
		/* a header that claims more rows than the section holds: nothing read */
		e.x[0].n = go_tab(g, magics[m], 1, 1000000);
		etab(elf_make(&e), &t);
		{
			struct kgenome_fntab_list l;

			memset(&l, 0, sizeof l);
			kgenome_fntab_gopcln(kof_buf_make(EB, sizeof EB), &t.ei, &l);
			CK(l.n == 0u);
			kgenome_fntab_list_free(&l);
		}
		CK(t.fs.ccase == KGENOME_FNTAB_C_NO_META && t.fs.v && n_high(&t.fs) == 0u && dfn(&t.fs, TEXT, 11, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED));  /* a table that gives nothing: no metadata; the entry derives (phase 2) */
		kgenome_funcs_free(&t.fs);
	}
}

static void t_trust_symtab(void)
{
	uint8_t text[0x60];
	struct eo e;
	struct et t;
	static const struct sym1 s[2] = { { "a", BASE + TEXT, 0x20, 0x12 }, { "b", BASE + TEXT + 0x20, 0, 0x12 } };

	memset(&e, 0, sizeof e);
	e.c64 = 1; e.em = 62; e.sections = 1;
	e.text = text; e.text_n = calls_text(text);
	e.sym = s; e.nsym = 2;
	etab(elf_make(&e), &t);
	CK(t.ok && t.fs.ccase == KGENOME_FNTAB_C_ELF_SYMTAB);
	{
		const struct kgenome_func *a = fat(&t.fs, TEXT), *b = fat(&t.fs, TEXT + 0x20);

		CK(a && a->trust == KGENOME_FN_TRUST_HIGH);
		/* round 4: a size-0 symbol declares a start, not a body; phase 2: the descent from that start derives b, and B, which a calls, is no start of it
		 * (a is exact: the descent does not read it, so its call to B is not seen) */
		CK(b && b->trust == KGENOME_FN_TRUST_DERIVED && b->len == 6 && b->source == (KGENOME_FN_S_SYMTAB | KGENOME_FN_S_DERIVED_SEED) &&
		   sat(&t.fs, TEXT + 0x20)->source == KGENOME_FN_S_SYMTAB);
	}
	{
		const struct kgenome_func *c = fat(&t.fs, TEXT + 0x40);

		CK(!c || c->trust == KGENOME_FN_TRUST_NONE);    /* a call target only exact code names is not a start */
	}
	kgenome_funcs_free(&t.fs);
	CK(!strcmp(kgenome_fn_trust_name(KGENOME_FN_TRUST_NONE), "none") && !strcmp(kgenome_fn_trust_name(KGENOME_FN_TRUST_HIGH), "high") &&
	   !strcmp(kgenome_fn_trust_name(2), "?") && !strcmp(kgenome_fn_trust_name(0), "-") && !strcmp(kgenome_fn_trust_name(9), "?"));
}

/* PE x64: .pdata with F [0x1000,0x1020) and a chained part P [0x1100,0x1110) whose parent is F; the part is far from F (0xe0 bytes between). */
static void t_pdata_parts(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0, x, ux;
	uint8_t *c;

	pb_init(&p, 0x4000, 1, 0x8664);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".rdata", 0x2000, 0x200, 0x200, CH_RDATA);
	pb_entry(&p, 0x1000);
	c = p.b + t0;
	memset(c, 0xcc, 0x200);
	memcpy(c, "\x48\x83\xec\x28\xe8\xf7\x00\x00\x00\x48\x83\xc4\x28\xc3", 14);  /* sub rsp; call 0x1100 (the far part: as if it were a function); add; ret */
	memcpy(c + 0x100, "\x90\x90\xc3", 3);
	x = off_of(&p, 0x2000);
	ux = 0x2100;
	/* the table: F, then P */
	w(p.b + x + 0, 0x1000, 4); w(p.b + x + 4, 0x1020, 4); w(p.b + x + 8, ux, 4);
	w(p.b + x + 12, 0x1100, 4); w(p.b + x + 16, 0x1110, 4); w(p.b + x + 20, ux + 0x10, 4);
	/* unwind info of F: version 1, no codes; of P: version 1, CHAININFO, no codes, then the parent's RUNTIME_FUNCTION */
	{
		uint8_t *u = p.b + off_of(&p, ux);

		u[0] = 1; u[2] = 0;
		u[0x10] = (uint8_t)(1u | (4u << 3)); u[0x12] = 0;
		w(u + 0x14, 0x1000, 4); w(u + 0x18, 0x1020, 4); w(u + 0x1c, ux, 4);
	}
	pb_dir(&p, KGENOME_PE_DIR_EXCEPTION, 0x2000, 24);
	pb_done(&p);
	build(p.b, p.n, &t);
	CK(t.ok && t.fs.ccase == KGENOME_FNTAB_C_PE_PDATA);
	CK(atz(&t, t0)->len == 0x20u && atz(&t, t0)->trust == KGENOME_FN_TRUST_HIGH);
	CK(!at(&t, t0 + 0x100));                                   /* the part is no function of its own (old: the walk made it one, a call target) */
	{
		const uint32_t fi = kgenome_funcs_start(&t.fs, t0);
		const struct kgenome_func_range r1 = kgenome_funcs_range(&t.fs, fi, 1);

		CK(fi != KGENOME_FUNCS_NONE && kgenome_funcs_n_ranges(&t.fs, fi) == 2u);
		CK(r1.off == t0 + 0x100u && r1.len == 0x10u && r1.fn == fi);
		CK(kgenome_funcs_at(&t.fs, t0 + 0x108) == fi && kgenome_funcs_at(&t.fs, t0 + 0x110) != fi);
		CK(kgenome_funcs_range(&t.fs, fi, 2).fn == KGENOME_FUNCS_NONE && kgenome_funcs_n_ranges(&t.fs, t.fs.n) == 0u);
		CK(t.fs.n_rng == 1u && t.fs.n_rng_orphan == 0u);
	}
	tab_free(&t);
	/* a part that lies INSIDE its root's body (an overlapping table, hostile or odd): it covers nothing new, and the undeclared code after the body starts
	 * at the body's end, not at the part's (mutant: the sweep moved back to the part's end and made an entry inside f) */
	w(p.b + x + 12, 0x1008, 4); w(p.b + x + 16, 0x1010, 4);
	build(p.b, p.n, &t);
	CK(t.ok && !at(&t, t0 + 0x10) && atz(&t, t0)->len == 0x20u);
	{
		uint32_t i;

		for (i = 1; i < t.fs.n; i++)
			CK(t.fs.v[i - 1u].off + t.fs.v[i - 1u].len <= t.fs.v[i].off);       /* no two entries share a byte */
	}
	tab_free(&t);
	w(p.b + x + 12, 0x1100, 4); w(p.b + x + 16, 0x1110, 4);
	/* the part's parent is no entry of the table (its RVA is code with no .pdata row): an orphan, counted */
	{
		uint8_t *u = p.b + off_of(&p, ux);

		w(u + 0x14, 0x1180, 4); w(u + 0x18, 0x1190, 4);
	}
	build(p.b, p.n, &t);
	CK(t.ok && t.fs.n_rng == 0u && t.fs.n_rng_orphan == 1u && kgenome_funcs_at(&t.fs, t0 + 0x108) != KGENOME_FUNCS_NONE &&
	   t.fs.v[kgenome_funcs_at(&t.fs, t0 + 0x108)].trust == KGENOME_FN_TRUST_NONE);   /* the orphan part's bytes are undeclared code (round 2) */
	tab_free(&t);
	/* the part's parent lies in a code section the file holds no byte of (pe120: 142_046 & co., a section with VirtualSize and no raw data): the part is
	 * not refused in silence - it is counted as an orphan (round 3), and its bytes are undeclared code */
	{
		uint8_t *u = p.b + off_of(&p, ux);

		w(u + 0x14, 0x1180 + 0x100, 4); w(u + 0x18, 0x1190 + 0x100, 4);       /* .text VirtualSize 0x300 over 0x200 raw bytes */
		w(p.b + p.sec_tab + 8, 0x300, 4);
	}
	build(p.b, p.n, &t);
	CK(t.ok && t.fs.n_rng == 0u && t.fs.n_rng_orphan == 1u && !(t.fs.partial & KGENOME_FNTAB_P_BAD_FDE));
	CK(kgenome_funcs_at(&t.fs, t0 + 0x108) != KGENOME_FUNCS_NONE && t.fs.v[kgenome_funcs_at(&t.fs, t0 + 0x108)].trust == KGENOME_FN_TRUST_NONE);
	tab_free(&t);
	free(p.b);
}

/* PE x86 with no table of any kind: one unit of trust NONE. */
static void t_pe_nometa(void)
{
	struct pb p;
	struct tab t;
	uint32_t t0;

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x100, 0x100, CH_CODE);
	pb_entry(&p, 0x1000);
	memset(p.b + t0, 0xcc, 0x100);
	memcpy(p.b + t0, "\xe8\x1b\x00\x00\x00\xc3", 6);            /* call 0x1020: the old walk made 0x1020 a function */
	memcpy(p.b + t0 + 0x20, "\x55\x8b\xec\x5d\xc3", 5);
	pb_done(&p);
	build(p.b, p.n, &t);
	/* phase 2: the entry derives `call 0x1020; ret` and the function it calls; the int3 runs stay NONE */
	CK(t.ok && dfn(&t.fs, t0, 6, KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED) && dfn(&t.fs, t0 + 0x20, 5, KGENOME_FN_S_DERIVED_CALL) && t.fs.n == 4u);
	CK(t.fs.ccase == KGENOME_FNTAB_C_NO_META && (t.fs.partial & KGENOME_FNTAB_P_NO_META) && t.fs.state == KGENOME_FNTAB_PARTIAL);
	tab_free(&t);
	free(p.b);
}

/* COVERAGE ROUND (gcov of the new strategies, 2026-11-16): the branches the rows above left unexecuted, each attacked here. */
static void t_more(void)
{
	uint8_t text[0x80], arr[16], tab[16], g[160];
	struct eo e;
	struct et t;
	struct kgenome_fntab_list l;
	uint32_t w32[4];

	/* initarr, ELF32 ARM: 4-byte pointers, a Thumb pointer (bit 0) is the even address with isa THUMB */
	memset(text, 0, sizeof text);
	memset(&e, 0, sizeof e);
	e.c64 = 0; e.em = 40; e.sections = 1; e.text = text; e.text_n = sizeof text;
	e.x[0] = (struct xsec){ ".init_array", 14, 3, arr, 8, 0 };
	e.nx = 1;
	lay_x(&e);
	w32[0] = BASE + TEXT + 0x21u; w32[1] = BASE + TEXT + 0x40u;
	memcpy(arr, w32, 8);
	etab(elf_make(&e), &t);
	{
		/* round 4: the two pointers are declared starts (the Thumb one even, isa THUMB) */
		CK(t.ok && sat(&t.fs, TEXT + 0x20)->isa_mode == KGENOME_FN_ISA_THUMB && (sat(&t.fs, TEXT + 0x20)->source & KGENOME_FN_S_INITARR) && sat(&t.fs, TEXT + 0x40)->source != 0);
	}
	kgenome_funcs_free(&t.fs);
	/* a dynamic table that names an array at an address no segment holds, and DT_PREINIT_ARRAY: counted, nothing followed */
	{
		static uint64_t dyn[8];

		memset(&e, 0, sizeof e);
		e.c64 = 1; e.em = 62; e.sections = 0; e.text = text; e.text_n = 0x40;
		dyn[0] = 32; dyn[1] = 0x9000000u; dyn[2] = 33; dyn[3] = 8; dyn[4] = 0x6ffffef5u; dyn[5] = 1; dyn[6] = 0; dyn[7] = 0;
		e.x[0] = (struct xsec){ ".dynamic", 6, 3, (const uint8_t *)dyn, sizeof dyn, 0 };
		e.nx = 1;
		e.g[0] = (struct xseg){ 2, 0 };
		e.ng = 1;
		etab(elf_make(&e), &t);
		memset(&l, 0, sizeof l);
		kgenome_fntab_initarr(kof_buf_make(EB, sizeof EB), &t.ei, &l);
		CK(t.ok && l.n == 0 && l.n_bad == 1);
		kgenome_fntab_list_free(&l);
		CK(t.fs.ccase == KGENOME_FNTAB_C_NO_META);      /* the table names nothing: no metadata */
		kgenome_funcs_free(&t.fs);
	}
	/* exidx: a row whose start is no code (an address past every segment) is counted */
	memset(&e, 0, sizeof e);
	e.c64 = 0; e.em = 40; e.sections = 1; e.text = text; e.text_n = sizeof text;
	e.x[0] = (struct xsec){ ".ARM.exidx", 0x70000001u, 0x82, tab, sizeof tab, 0 };
	e.nx = 1;
	lay_x(&e);
	memset(tab, 0, sizeof tab);
	w32[0] = (uint32_t)((BASE + TEXT - (BASE + e.x[0].off)) & 0x7fffffffu); w32[1] = 1;
	w32[2] = (uint32_t)((BASE + 0x8000u - (BASE + e.x[0].off + 8u)) & 0x7fffffffu); w32[3] = 1;
	memcpy(tab, w32, sizeof w32);
	etab(elf_make(&e), &t);
	memset(&l, 0, sizeof l);
	kgenome_fntab_exidx(kof_buf_make(EB, sizeof EB), &t.ei, &l);
	CK(t.ok && l.n == 1 && l.n_bad == 1);
	kgenome_fntab_list_free(&l);
	kgenome_funcs_free(&t.fs);
	/* gopcln: Go 1.16 (pclnOffset 6 words in), Go 1.20 with textStart 0 (a PIE: .text stands for it), an unknown magic, and a row that leaves the segment */
	{
		static const uint32_t magics[2] = { 0xfffffff1u, 0xfffffffau };     /* Go 1.16 last: the row below edits its table */
		unsigned m;

		for (m = 0; m < 2u; m++) {
			uint64_t nf = 2, rows = 80, zero = 0;

			memset(g, 0, sizeof g);
			memcpy(g, &magics[m], 4);
			g[6] = 1; g[7] = 8;
			memcpy(g + 8, &nf, 8);
			if (m == 1) {
				const uint64_t r[5] = { BASE + TEXT, 0, BASE + TEXT + 0x30u, 0, BASE + TEXT + 0x60u };

				memcpy(g + 8 + 6 * 8, &rows, 8);
				memcpy(g + rows, r, sizeof r);
			} else {
				const uint32_t r[5] = { 0, 0, 0x30, 0, 0x60 };

				memcpy(g + 8 + 2 * 8, &zero, 8);
				memcpy(g + 8 + 7 * 8, &rows, 8);
				memcpy(g + rows, r, sizeof r);
			}
			memset(&e, 0, sizeof e);
			e.c64 = 1; e.em = 62; e.sections = 1; e.text = text; e.text_n = 0x60;
			e.x[0] = (struct xsec){ ".gopclntab", 1, 2, g, sizeof g, 0 };
			e.nx = 1;
			etab(elf_make(&e), &t);
			{
				const struct kgenome_func *g1 = fat(&t.fs, TEXT + 0x30);

				CK(t.ok && t.fs.ccase == KGENOME_FNTAB_C_ELF_GO && fat(&t.fs, TEXT) && g1 && g1->len == 0x30u);
			}
			kgenome_funcs_free(&t.fs);
		}
		/* the same Go 1.16 table whose last row runs past the segment: the row is refused, counted */
		{
			const uint64_t far = BASE + 0x9000u;

			memcpy(g + 80 + 32, &far, 8);
			etab(elf_make(&e), &t);
			memset(&l, 0, sizeof l);
			kgenome_fntab_gopcln(kof_buf_make(EB, sizeof EB), &t.ei, &l);
			CK(l.n == 1 && l.n_bad == 1);
			kgenome_fntab_list_free(&l);
			kgenome_funcs_free(&t.fs);
		}
		memset(g, 0x11, 4);                             /* an unknown magic: nothing read */
		etab(elf_make(&e), &t);
		memset(&l, 0, sizeof l);
		kgenome_fntab_gopcln(kof_buf_make(EB, sizeof EB), &t.ei, &l);
		CK(l.n == 0 && l.n_bad == 0);
		kgenome_fntab_list_free(&l);
		kgenome_funcs_free(&t.fs);
	}
	/* the entry strategy: NA and BROKEN are no entry; NULL arguments read nothing */
	memset(&l, 0, sizeof l);
	kgenome_fntab_entry((uint64_t)-1, 0, &l);
	kgenome_fntab_entry((uint64_t)-2, 1, &l);
	kgenome_fntab_entry(0x10, 0, NULL);
	CK(l.n == 0);
	kgenome_fntab_initarr(kof_buf_make(NULL, 0), NULL, &l);
	kgenome_fntab_exidx(kof_buf_make(NULL, 0), NULL, &l);
	kgenome_fntab_gopcln(kof_buf_make(NULL, 0), NULL, &l);
	CK(l.n == 0 && l.n_bad == 0);
}

/* INS-1 (round 4, coordinator M: gcc -O1 -fno-asynchronous-unwind-tables, stripped: frame_dummy's init_array start became ONE unit holding a, b and main).
 * A start-only table declares a START, not a body: the code stays one NONE unit, uncut, and carries its declared starts. RED before round 4: the start
 * was a MEDIUM unit running to the next start or the end of .text. */
static void t_ins1(void)
{
	uint8_t text[0x60], arr[8], tab[16];
	struct eo e;
	struct et t;
	uint32_t first = 0, row;

	/* (a) .init_array names the entry function only (the entry point is the same start); a and b behind it are declared by nothing */
	memset(&e, 0, sizeof e);
	e.c64 = 1; e.em = 62; e.sections = 1; e.text = text; e.text_n = calls_text(text);
	e.x[0] = (struct xsec){ ".init_array", 14, 3, arr, sizeof arr, 0 };
	e.nx = 1;
	memcpy(arr, &(uint64_t){ BASE + TEXT }, 8);
	etab(elf_make(&e), &t);
	/* phase 2: the descent from the declared start derives the entry function (11 bytes, not the 0x60 the INS-1 unit swallowed) and the two it calls, a
	 * and b, each its own extent */
	CK(t.ok && n_high(&t.fs) == 0u && dfn(&t.fs, TEXT, 11, KGENOME_FN_S_INITARR | KGENOME_FN_S_ENTRY | KGENOME_FN_S_DERIVED_SEED));
	CK(kgenome_funcs_starts_in(&t.fs, kgenome_funcs_start(&t.fs, TEXT), &first) == 1u && t.fs.n_st == 1u);
	CK(t.fs.n_st && t.fs.st[first].off == TEXT && (t.fs.st[first].source & KGENOME_FN_S_INITARR) && (t.fs.st[first].source & KGENOME_FN_S_ENTRY));
	CK(dfn(&t.fs, TEXT + 0x20, 6, KGENOME_FN_S_DERIVED_CALL) && dfn(&t.fs, TEXT + 0x40, 6, KGENOME_FN_S_DERIVED_CALL));
	kgenome_funcs_free(&t.fs);
	/* (b) ARM: .ARM.exidx rows at 0x00 and 0x40, the leaf at 0x20 has no row (EHABI 5.3): one NONE unit with two declared starts, not cut at either */
	memset(text, 0, sizeof text);
	memset(&e, 0, sizeof e);
	e.c64 = 0; e.em = 40; e.sections = 1; e.text = text; e.text_n = sizeof text;
	e.x[0] = (struct xsec){ ".ARM.exidx", 0x70000001u, 0x82, tab, sizeof tab, 0 };
	e.nx = 1;
	lay_x(&e);
	for (row = 0; row < 2; row++) {
		const uint64_t va = BASE + e.x[0].off + 8u * row, to = BASE + TEXT + (row ? 0x40u : 0u);
		const uint32_t w0 = (uint32_t)((to - va) & 0x7fffffffu), w1 = 1u;

		memcpy(tab + 8u * row, &w0, 4);
		memcpy(tab + 8u * row + 4u, &w1, 4);
	}
	etab(elf_make(&e), &t);
	/* phase 2: zeros (`andeq r0, r0, r0`) read from 0x00 run into the row at 0x40. 2026-11-17: an unwind row the code before it runs into declares no entry
	 * (fntab_derive.c is_entry), so it is ONE derived function to the end of the code; the row stays a declared start (it was two functions: the rule changed) */
	CK(t.ok && t.fs.n == 1u && dfn(&t.fs, TEXT, 0x60, KGENOME_FN_S_EXIDX | KGENOME_FN_S_DERIVED_SEED) && kgenome_funcs_start(&t.fs, TEXT + 0x40) == KGENOME_FUNCS_NONE);
	CK(kgenome_funcs_starts_in(&t.fs, 0, &first) == 2u && t.fs.n_st == 2u && t.fs.st[1].off == TEXT + 0x40u && (t.fs.st[1].source & KGENOME_FN_S_EXIDX));
	kgenome_funcs_free(&t.fs);
}

int main(void)
{
	t_nometa();
	t_initarr();
	t_exidx();
	t_exidx_inside();
	t_gopcln();
	t_trust_symtab();
	t_pdata_parts();
	t_pe_nometa();
	t_more();
	t_ins1();
	printf("fntab_meta: %s (%d failures)\n", fails ? "FAIL" : "ok", fails);
	return fails ? 1 : 0;
}
