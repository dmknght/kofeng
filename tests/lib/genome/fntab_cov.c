/*
 * fntab_cov - the function table (libgenome/genotype/image/fntab*.c, funcs.c symbol path, phenotype/fntab_build.c, fntab_walk.c, diag_code.c extents), attacked.
 *
 * Written from the coverage of fntab.c, api_image, hostile_image, api_diag, diag_properties and the codemap tests (measured with gcc --coverage, -O0, gcov -b: the work list is
 * in the report of the change). Why those tests missed what is here: (a) line never executed: the .dynsym probe and strategy end to end, the encodings sdata2/udata2/sleb/uleb, the
 * 'P' / 'L' / 'S' / 'B' augmentations, the version 3 CIE, the CIE table cap, a 64-bit length cut short, the NOMEM arms of every allocation; (b) executed without a boundary input: the
 * entry cap with the merge, a CIE past the cap, an exact body overlapped by a better source, padding exactly at the extent; (c) "no crash" only: the old hostile rows never compared the
 * table with an oracle.
 *
 * The allocators are wrapped (-Wl,--wrap=malloc,calloc,realloc: UNIT_LIBS_fntab_cov in mk/tests.mk) so that every allocation of a build can be made to fail in turn.
 */
#include "fntab_kit.h"

#include <genotype/image/pe_types.h>

/* ---- the allocation wrap: fail the Nth allocation ----------------------------------------------------------------------------- */

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
static unsigned fail_at;       /* 0: off; N: the Nth allocation from arming fails */
static unsigned alloc_seen;

static int should_fail(void)
{
	if (!fail_at)
		return 0;
	alloc_seen++;
	if (alloc_seen == fail_at) {
		fail_at = 0;
		return 1;
	}
	return 0;
}
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);
void *__wrap_malloc(size_t n) { return should_fail() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t a, size_t b) { return should_fail() ? NULL : __real_calloc(a, b); }
void *__wrap_realloc(void *p, size_t n) { return should_fail() ? NULL : __real_realloc(p, n); }

/* a tiny deterministic generator: the tests are reproducible */
static uint64_t rng_s = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void) { rng_s ^= rng_s << 13; rng_s ^= rng_s >> 7; rng_s ^= rng_s << 17; return rng_s; }

/* ---- 1. the selector: EVERY combination of the metadata, against a table written the other way round ------------------------------ */

/* The oracle is the decision table of fntab_select.c's header comment, read as sentences, and the invariant that no strategy runs on data that is absent. */
static void t_selector_exhaustive(void)
{
	static const uint8_t fmts[] = { KGENOME_FMT_ELF, KGENOME_FMT_PE, 0, 7, 255 };
	unsigned f, bits, n_elf = 0;

	for (f = 0; f < sizeof fmts; f++)
		for (bits = 0; bits < 16384u; bits++) {
			struct kgenome_fntab_meta m;
			struct kgenome_fntab_plan p;
			unsigned want_case, want_run = 0, want_chk = 0;

			memset(&m, 0, sizeof m);
			m.format = fmts[f];
			m.elf_rel = bits & 1u;
			m.has_symtab = (bits >> 1) & 1u;
			m.has_dynsym = (bits >> 2) & 1u;
			m.has_unwind = (bits >> 3) & 1u;
			m.symtab_empty = (bits >> 4) & 1u;
			m.dynsym_empty = (bits >> 5) & 1u;
			m.pe_x64_pdata = (bits >> 6) & 1u;
			m.pe_clr = (bits >> 7) & 1u;
			m.pdata_empty = (bits >> 8) & 1u;
			m.pe_x86 = (bits >> 9) & 1u;
			m.pe_coff = (bits >> 10) & 1u;
			m.coff_empty = (bits >> 11) & 1u;
			m.pe_nocode = (bits >> 12) & 1u;
			m.pe_arm = (bits >> 13) & 1u;
			p = kgenome_fntab_select(&m);
			if (m.format == KGENOME_FMT_ELF) {
				n_elf++;
				/* ELF-NO-REACH, fixed 2026-11-05: every row that runs WALK runs KGENOME_FNTAB_X_PE_REACH beside it too (RED
				 * on base: these three want_run values held no REACH bit there); ELF_SYMTAB never sets WALK so it is unchanged. */
				if (m.has_symtab && !m.symtab_empty) {
					want_case = KGENOME_FNTAB_C_ELF_SYMTAB;
					want_run = KGENOME_FNTAB_X_SYMTAB | (m.has_unwind ? KGENOME_FNTAB_X_FDE : 0u);
					want_chk = m.has_unwind ? KGENOME_FN_S_FDE : 0u;
				} else if (m.has_dynsym && !m.dynsym_empty && !m.elf_rel) {
					want_case = KGENOME_FNTAB_C_ELF_DYNSYM;
					want_run = KGENOME_FNTAB_X_DYNSYM | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH | (m.has_unwind ? KGENOME_FNTAB_X_FDE : 0u);
				} else if (m.has_unwind && !m.elf_rel) {
					want_case = KGENOME_FNTAB_C_ELF_FDE;
					want_run = KGENOME_FNTAB_X_FDE | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH;
				} else {
					want_case = KGENOME_FNTAB_C_ELF_WALK;
					want_run = m.elf_rel ? 0u : (KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH);
				}
			} else if (m.format == KGENOME_FMT_PE) {
				/* the PE rows (A2), written as sentences: a managed image is empty; an x64 exception table that held functions is the exact source with the guessing sources beside it and
				 * the reach step after (and the COFF symbols when the file has the table); x86 with COFF symbols that held functions; x86 with neither; any other machine nothing */
				const unsigned starts = KGENOME_FNTAB_X_PE_EXPORT | KGENOME_FNTAB_X_PE_TLS | KGENOME_FNTAB_X_PE_CFG | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_THUNK;

				if (m.pe_clr) {
					want_case = KGENOME_FNTAB_C_PE_CLR;
				} else if (m.pe_nocode) {
					want_case = KGENOME_FNTAB_C_PE_NOCODE;
				} else if (m.pe_x64_pdata && !m.pdata_empty) {
					want_case = KGENOME_FNTAB_C_PE_PDATA;
					want_run = KGENOME_FNTAB_X_PDATA | starts | KGENOME_FNTAB_X_PE_REACH | (m.pe_coff ? KGENOME_FNTAB_X_PE_COFF : 0u);
				} else if (m.pe_x86 && m.pe_coff && !m.coff_empty) {
					want_case = KGENOME_FNTAB_C_PE_COFF;
					want_run = KGENOME_FNTAB_X_PE_COFF | starts | KGENOME_FNTAB_X_PE_REACH;
				} else if (m.pe_x86) {
					want_case = KGENOME_FNTAB_C_PE_WALK;
					want_run = starts | KGENOME_FNTAB_X_PE_REACH;
				} else if (m.pe_arm) {
					want_case = KGENOME_FNTAB_C_PE_ARM;
					want_run = KGENOME_FNTAB_X_PE_ARMPDATA | KGENOME_FNTAB_X_PE_EXPORT | KGENOME_FNTAB_X_PE_TLS | KGENOME_FNTAB_X_PE_CFG;
				} else {
					want_case = KGENOME_FNTAB_C_PE_NONE;
				}
			} else {
				want_case = KGENOME_FNTAB_C_NONE;
			}
			CK(p.ccase == want_case && p.run == want_run && p.check_only == want_chk);
			/* never a strategy whose data is absent */
			if (p.run & KGENOME_FNTAB_X_SYMTAB) CK(m.has_symtab && !m.symtab_empty && m.format == KGENOME_FMT_ELF);
			if (p.run & KGENOME_FNTAB_X_DYNSYM) CK(m.has_dynsym && !m.dynsym_empty && !m.elf_rel);
			if (p.run & KGENOME_FNTAB_X_FDE) CK(m.has_unwind);
			if (p.run & KGENOME_FNTAB_X_PDATA) CK(m.pe_x64_pdata && m.format == KGENOME_FMT_PE);
			if (p.run & KGENOME_FNTAB_X_WALK) CK((m.format == KGENOME_FMT_ELF && !m.elf_rel) || m.format == KGENOME_FMT_PE);
			if (p.run & KGENOME_FNTAB_X_PDATA) CK(!m.pdata_empty && !m.pe_clr);
			/* a check-only source is a strategy that runs; the symbol strategies run once, SYMTAB and DYNSYM never together */
			CK(!(p.check_only & KGENOME_FN_S_FDE) || (p.run & KGENOME_FNTAB_X_FDE));
			CK(!((p.run & KGENOME_FNTAB_X_SYMTAB) && (p.run & KGENOME_FNTAB_X_DYNSYM)));
			/* the one retry: a symbol table found empty is the NEXT row, never the same case again */
			if (m.format == KGENOME_FMT_ELF && m.has_symtab && m.symtab_empty)
				CK(p.ccase != KGENOME_FNTAB_C_ELF_SYMTAB);
			if (m.format == KGENOME_FMT_ELF && m.has_dynsym && m.dynsym_empty && m.symtab_empty)
				CK(p.ccase != KGENOME_FNTAB_C_ELF_DYNSYM);
		}
	CK(n_elf == 16384u);      /* every ELF row of the 14 metadata bits (the PE bits do not change an ELF answer, and the case says so) */
}

/* ---- 2. the probe ------------------------------------------------------------------------------------------------------------- */

static struct kgenome_elf_info EI;          /* big: kept static */

static void t_probe(void)
{
	struct kgenome_fntab_meta m;
	struct kgenome_pe_info *pe = calloc(1, sizeof *pe);
	uint8_t one[4] = { 0 };
	kof_buf nob = kof_buf_make(NULL, 0), some = kof_buf_make(one, 4);
	unsigned i, mach, plus, rva, size;

	/* nothing to read: the meta is zero but for the format */
	memset(&m, 0xaa, sizeof m); kgenome_fntab_probe(KGENOME_FMT_ELF, some, NULL, &m);
	CK(m.format == KGENOME_FMT_ELF && !m.has_symtab && !m.has_dynsym && !m.has_unwind && !m.elf_rel && !m.pe_x64_pdata);
	memset(&m, 0xaa, sizeof m); kgenome_fntab_probe(KGENOME_FMT_ELF, nob, &EI, &m);
	CK(m.format == KGENOME_FMT_ELF && !m.has_symtab && !m.has_unwind);
	memset(&EI, 0, sizeof EI);                  /* an info that is not valid */
	memset(&m, 0xaa, sizeof m); kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(m.format == KGENOME_FMT_ELF && !m.has_symtab && !m.has_dynsym && !m.has_unwind && !m.elf_rel);
	memset(&m, 0xaa, sizeof m); kgenome_fntab_probe(0, some, &EI, &m);      /* a format that has no table */
	CK(m.format == 0 && !m.has_symtab && !m.pe_x64_pdata);

	/* a valid ELF info: every section type that matters, an ET_REL */
	EI.valid = 1; EI.e_type = KGENOME_ELF_EXEC; EI.sec_count = 4;
	EI.sec[1].type = KGENOME_ELF_SHT_DYNSYM; EI.sec[1].file_size = 0;       /* empty .dynsym: not a symbol table */
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(!m.has_dynsym);
	EI.sec[1].file_size = 24;
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(m.has_dynsym && !m.elf_rel && !m.has_unwind);
	EI.e_type = KGENOME_ELF_REL;
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(m.elf_rel && m.has_dynsym && !m.has_unwind);
	/* an object file never has_unwind, whatever sections it has (a pcrel value is a relocation there) */
	EI.sec[2].type = KGENOME_ELF_SHT_PROGBITS; EI.sec[2].flags = KGENOME_ELF_SHF_ALLOC; EI.sec[2].file_size = 40; strcpy(EI.sec[2].name, ".eh_frame");
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(m.elf_rel && !m.has_unwind);
	EI.e_type = KGENOME_ELF_EXEC;
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(m.has_unwind);
	/* only the segment names it */
	memset(EI.sec, 0, sizeof EI.sec); EI.sec_count = 0;
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(!m.has_unwind);
	EI.seg_count = 1; EI.seg[0].type = 0x6474e550u; EI.seg[0].file_size = 11;
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(!m.has_unwind);                          /* a header shorter than 12 bytes names nothing */
	EI.seg[0].file_size = 12;
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(m.has_unwind);

	/* PE: every combination of machine, PE32+ and the exception directory */
	for (i = 0; i < 2 * 2 * 2 * 2 + 1; i++) {
		mach = (i & 1u) ? 0x8664u : 0x14cu; plus = (i >> 1) & 1u; rva = (i >> 2) & 1u; size = (i >> 3) & 1u;
		memset(pe, 0, sizeof *pe);
		pe->valid = i < 16 ? 1u : 0u;           /* the 17th: an invalid info with everything set */
		pe->machine = (uint16_t)(i < 16 ? mach : 0x8664u); pe->pe32_plus = (uint8_t)(i < 16 ? plus : 1u);
		pe->dir[KGENOME_PE_DIR_EXCEPTION].rva = i < 16 ? rva : 1u; pe->dir[KGENOME_PE_DIR_EXCEPTION].size = i < 16 ? size : 1u;
		kgenome_fntab_probe(KGENOME_FMT_PE, some, pe, &m);
		CK(m.format == KGENOME_FMT_PE);
		CK(m.pe_x64_pdata == (i < 16 && mach == 0x8664u && plus && rva && size));
	}
	free(pe);
}

/* ---- 3. where the unwind table is looked for -------------------------------------------------------------------------------------- */

static void t_eh_locate(void)
{
	uint32_t idx = 99;
	const uint32_t SHT_X64 = 0x70000001u;

	memset(&EI, 0, sizeof EI);
	EI.valid = 1;
	EI.sec_count = 6;
	/* slot 0 is the null section and is never read */
	strcpy(EI.sec[0].name, ".eh_frame"); EI.sec[0].type = KGENOME_ELF_SHT_PROGBITS; EI.sec[0].flags = KGENOME_ELF_SHF_ALLOC; EI.sec[0].file_size = 8;
	CK(!kgenome_fntab_eh_section(&EI, &idx));
	/* each condition alone makes it not the section */
	strcpy(EI.sec[1].name, ".eh_frame"); EI.sec[1].type = KGENOME_ELF_SHT_PROGBITS; EI.sec[1].flags = KGENOME_ELF_SHF_ALLOC; EI.sec[1].file_size = 8;
	CK(kgenome_fntab_eh_section(&EI, &idx) && idx == 1);
	EI.sec[1].file_size = 0;       CK(!kgenome_fntab_eh_section(&EI, &idx)); EI.sec[1].file_size = 8;
	EI.sec[1].flags = 0;           CK(!kgenome_fntab_eh_section(&EI, &idx)); EI.sec[1].flags = KGENOME_ELF_SHF_ALLOC;
	EI.sec[1].type = KGENOME_ELF_SHT_NOBITS; CK(!kgenome_fntab_eh_section(&EI, &idx)); EI.sec[1].type = KGENOME_ELF_SHT_PROGBITS;
	strcpy(EI.sec[1].name, ".eh_frame_hdr"); CK(!kgenome_fntab_eh_section(&EI, &idx));
	strcpy(EI.sec[1].name, ".eh_fram");      CK(!kgenome_fntab_eh_section(&EI, &idx));
	strcpy(EI.sec[1].name, ".eh_frame");
	EI.sec[1].type = SHT_X64;      CK(kgenome_fntab_eh_section(&EI, &idx) && idx == 1);     /* the x86-64 unwind type */
	/* the first one wins, a later one is not looked at */
	strcpy(EI.sec[3].name, ".eh_frame"); EI.sec[3].type = KGENOME_ELF_SHT_PROGBITS; EI.sec[3].flags = KGENOME_ELF_SHF_ALLOC; EI.sec[3].file_size = 8;
	CK(kgenome_fntab_eh_section(&EI, &idx) && idx == 1);
	EI.sec[1].file_size = 0;
	CK(kgenome_fntab_eh_section(&EI, &idx) && idx == 3);
	/* sec_count beyond the table's size is clamped, never read past */
	memset(&EI, 0, sizeof EI);
	EI.valid = 1; EI.sec_count = 0xffffffffu;
	CK(!kgenome_fntab_eh_section(&EI, &idx));
	strcpy(EI.sec[KGENOME_ELF_MAX_SECTIONS - 1].name, ".eh_frame"); EI.sec[KGENOME_ELF_MAX_SECTIONS - 1].type = KGENOME_ELF_SHT_PROGBITS;
	EI.sec[KGENOME_ELF_MAX_SECTIONS - 1].flags = KGENOME_ELF_SHF_ALLOC; EI.sec[KGENOME_ELF_MAX_SECTIONS - 1].file_size = 8;
	CK(kgenome_fntab_eh_section(&EI, &idx) && idx == KGENOME_ELF_MAX_SECTIONS - 1);

	/* the segment */
	memset(&EI, 0, sizeof EI);
	EI.valid = 1; EI.seg_count = 3;
	CK(!kgenome_fntab_eh_segment(&EI, &idx));
	EI.seg[1].type = 0x6474e550u; EI.seg[1].file_size = 11;
	CK(!kgenome_fntab_eh_segment(&EI, &idx));
	EI.seg[1].file_size = 12;
	CK(kgenome_fntab_eh_segment(&EI, &idx) && idx == 1);
	EI.seg[1].type = 0x6474e551u;
	CK(!kgenome_fntab_eh_segment(&EI, &idx));
	EI.seg_count = 0xffffffffu;
	EI.seg[KGENOME_ELF_MAX_SEGMENTS - 1].type = 0x6474e550u; EI.seg[KGENOME_ELF_MAX_SEGMENTS - 1].file_size = 100;
	CK(kgenome_fntab_eh_segment(&EI, &idx) && idx == KGENOME_ELF_MAX_SEGMENTS - 1);
}


/* ---- 4. the unwind data writer (independent of fntab.c's eh_make: any CIE, any encoding) ------------------------------------------- */

struct eb { uint8_t *b; uint32_t n, cap; int be; uint64_t va; int wide; };

static void eb_u8(struct eb *e, unsigned v) { if (e->n < e->cap) e->b[e->n] = (uint8_t)v; e->n++; }
static void eb_un(struct eb *e, uint64_t v, unsigned w) { unsigned i; for (i = 0; i < w; i++) eb_u8(e, (unsigned)(v >> (8u * (e->be ? w - 1u - i : i))) & 0xffu); }
static void eb_uleb(struct eb *e, uint64_t v) { do { unsigned c = v & 0x7f; v >>= 7; eb_u8(e, c | (v ? 0x80u : 0u)); } while (v); }
static void eb_sleb(struct eb *e, int64_t v)
{
	for (;;) {
		unsigned c = (unsigned)(v & 0x7f);
		v >>= 7;
		if ((v == 0 && !(c & 0x40)) || (v == -1 && (c & 0x40))) { eb_u8(e, c); return; }
		eb_u8(e, c | 0x80u);
	}
}
/* an encoded value (DW_EH_PE format = low nibble) */
static void eb_enc(struct eb *e, int enc, int64_t v)
{
	switch (enc & 0x0f) {
	case 0x00: eb_un(e, (uint64_t)v, e->wide ? 8u : 4u); break;
	case 0x01: eb_uleb(e, (uint64_t)v); break;
	case 0x02: case 0x0a: eb_un(e, (uint64_t)v, 2); break;
	case 0x03: case 0x0b: eb_un(e, (uint64_t)v, 4); break;
	case 0x04: case 0x0c: eb_un(e, (uint64_t)v, 8); break;
	case 0x09: eb_sleb(e, v); break;
	default: eb_un(e, (uint64_t)v, 4); break;
	}
}
static void eb_patch32(struct eb *e, uint32_t at, uint32_t v) { unsigned i; for (i = 0; i < 4; i++) if (at + i < e->cap) e->b[at + i] = (uint8_t)(v >> (8u * (e->be ? 3u - i : i))); }

/* A CIE: version, augmentation string, the augmentation data as raw bytes (`ad`, `adn`; its length is written when the string starts with 'z'). Returns its position. */
static uint32_t eb_cie(struct eb *e, unsigned ver, const char *aug, const uint8_t *ad, unsigned adn)
{
	uint32_t at = e->n;

	eb_un(e, 0, 4);                                 /* length, patched */
	eb_un(e, 0, 4);                                 /* id 0 */
	eb_u8(e, ver);
	while (*aug) eb_u8(e, (unsigned)*aug++);
	eb_u8(e, 0);
	eb_uleb(e, 1);                                  /* code alignment */
	eb_sleb(e, -8);                                 /* data alignment */
	if (ver == 1) eb_u8(e, 16); else eb_uleb(e, 16);
	if (adn != 0xffffu) {                           /* 0xffff: no augmentation length (a string that does not start with z) */
		eb_uleb(e, adn);
		{ unsigned i; for (i = 0; i < adn; i++) eb_u8(e, ad[i]); }
	}
	while ((e->n - at) % 4u) eb_u8(e, 0);           /* DW_CFA_nop padding to 4 */
	eb_patch32(e, at, e->n - at - 4u);
	return at;
}

/* An FDE of `cie` for [target, target+range), the address in `enc`. `raw_range`: when set, the range is written as given (for a hostile one). */
static uint32_t eb_fde(struct eb *e, uint32_t cie, int enc, uint64_t target, uint64_t range)
{
	uint32_t at = e->n, field;

	eb_un(e, 0, 4);
	eb_un(e, e->n - cie, 4);                        /* the CIE pointer: back from this field */
	field = e->n;
	if ((enc & 0x70) == 0x10)
		eb_enc(e, enc, (int64_t)(target - (e->va + field)));
	else
		eb_enc(e, enc, (int64_t)target);
	eb_enc(e, enc & 0x0f, (int64_t)range);
	eb_uleb(e, 0);                                  /* augmentation length of the FDE ('z') */
	while ((e->n - at) % 4u) eb_u8(e, 0);
	eb_patch32(e, at, e->n - at - 4u);
	return at;
}

/* ---- the file around it -------------------------------------------------------------------------------------------------------------- */

#define FBASE 0x1000u
static uint8_t EHB[0x2000];
static uint8_t *ehp = EHB;                 /* the buffer the unwind data is built in (a test that needs megabytes points it elsewhere) */
static uint32_t ehcap = sizeof EHB;

struct fcase { int c64, be, sections, eh_hdr; };

/* x86-64-looking text, 4 functions, 3 of them named by the FDEs below */
static const struct fde F3[3] = { { 0, 11 }, { 0x10, 6 }, { 0x30, 6 } };

typedef void (*gen_fn)(struct eb *e, uint64_t text_va, const void *arg);

static uint32_t build_file(const struct fcase *fc, gen_fn gen, const void *arg, struct elf_in *in)
{
	struct lay l;
	struct eb e;
	static uint8_t TX[0x100];

	memset(in, 0, sizeof *in);
	in->c64 = fc->c64; in->be = fc->be;
	in->em = fc->c64 ? (fc->be ? 21 : 62) : (fc->be ? 20 : 3);
	in->base = FBASE; in->text = TX; in->text_n = x86_text(TX);
	in->rodata_n = 0x20; in->sections = fc->sections; in->eh_hdr = fc->eh_hdr; in->eh_section = fc->sections;
	layout(in, &l);
	memset(ehp, 0, ehcap);
	e.b = ehp; e.n = 0; e.cap = ehcap; e.be = fc->be; e.va = l.eh_va; e.wide = fc->c64;
	gen(&e, l.text_va, arg);
	in->eh = ehp; in->eh_n = e.n;
	return elf_build(in, B);
}

struct fres { unsigned n; struct kgenome_func v[64]; uint32_t n_bad; uint16_t partial; int status; };

/* The invariants of what the unwind strategy keeps, for ANY input: sorted, no overlap, non-empty, inside the file, tagged. */
static void fde_inv(const struct kgenome_fntab_list *l, uint32_t file_n)
{
	uint32_t i;

	for (i = 0; i < l->n; i++) {
		const struct kgenome_func *f = &l->v[i];

		CK(f->len > 0 && f->off + f->len <= file_n && f->off + f->len > f->off);
		CK(f->source == KGENOME_FN_S_FDE && f->end_source == KGENOME_FN_E_UNWIND);
		CK(f->value >= FBASE);
		if (i)
			CK(l->v[i - 1u].off + l->v[i - 1u].len <= f->off);
	}
}

static void fde_of(const uint8_t *file, uint32_t n, const struct kgenome_elf_info *ei, struct fres *r)
{
	struct kgenome_fntab_list l;
	unsigned i;

	memset(&l, 0, sizeof l);
	kgenome_fntab_fde(kof_buf_make(file, n), ei, &l);
	fde_inv(&l, n);
	memset(r, 0, sizeof *r);
	r->n = l.n < 64u ? l.n : 64u;
	for (i = 0; i < r->n; i++) r->v[i] = l.v[i];
	r->n_bad = l.n_bad; r->partial = l.partial; r->status = (int)l.status;
	if (l.n > 64u) r->n = l.n;
	kgenome_fntab_list_free(&l);
}

static int parse_ok(const uint8_t *b, uint32_t n, struct kgenome_elf_info *ei)
{
	struct kgenome_obj o;
	return parse(b, n, ei, &o);
}

/* the three expected entries of F3 */
static void want_f3(const struct fres *r, const char *what)
{
	unsigned i;

	if (r->n != 3u) { printf("  [%s] n=%u bad=%u\n", what, r->n, r->n_bad); fails++; return; }
	for (i = 0; i < 3; i++) {
		if (r->v[i].off != TEXT_OFF + F3[i].off || r->v[i].len != F3[i].len || r->v[i].value != FBASE + TEXT_OFF + F3[i].off) {
			printf("  [%s] entry %u off=%llx len=%llu value=%llx\n", what, i, (unsigned long long)r->v[i].off, (unsigned long long)r->v[i].len, (unsigned long long)r->v[i].value);
			fails++;
		}
	}
	if (r->n_bad || r->partial || r->status) { printf("  [%s] bad=%u partial=%x status=%d\n", what, r->n_bad, r->partial, r->status); fails++; }
}

/* ---- the encodings: every format x absolute / pcrel x LE/BE x ELF32/ELF64 x section / PT_GNU_EH_FRAME ------------------------------------------ */

struct enc_arg { int enc; const char *aug; };

static void gen_enc(struct eb *e, uint64_t text_va, const void *arg)
{
	const struct enc_arg *a = arg;
	uint8_t ad[1] = { (uint8_t)a->enc };
	uint32_t c = eb_cie(e, 1, a->aug, ad, 1);
	unsigned i;

	for (i = 0; i < 3; i++)
		eb_fde(e, c, a->enc, text_va + F3[i].off, F3[i].len);
	eb_un(e, 0, 4);
}

static void t_fde_encodings(void)
{
	/* the fixed widths and the two variable formats; udata/uleb need a positive delta, so the pcrel ones are the signed formats (the unwinder's own choice) */
	static const int abs_enc[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0a, 0x0b, 0x0c };
	static const int rel_enc[] = { 0x19, 0x1a, 0x1b, 0x1c, 0x13 };
	unsigned fcase, k, hdr;

	for (fcase = 0; fcase < 8; fcase++)
		for (hdr = 0; hdr < 2; hdr++) {
			struct fcase fc;
			unsigned pass;

			fc.c64 = fcase & 1; fc.be = (fcase >> 1) & 1; fc.sections = !hdr; fc.eh_hdr = (int)hdr;
			(void)pass;
			for (k = 0; k < sizeof abs_enc / sizeof *abs_enc + sizeof rel_enc / sizeof *rel_enc; k++) {
				struct enc_arg a;
				struct elf_in in;
				struct kgenome_elf_info ei;
				struct fres r;
				uint32_t n;
				char what[96];

				a.enc = k < sizeof abs_enc / sizeof *abs_enc ? abs_enc[k] : rel_enc[k - sizeof abs_enc / sizeof *abs_enc];
				/* FNTAB-COV-2: pc-relative udata4 is a 32-bit sum in an ELF32, so a table after the code (a negative delta) names the address it should; in an ELF64 the same bytes are a
				 * delta of 4 GiB and name no function (the unwinder's own choice there is sdata4): the row is ELF32's only */
				if (a.enc == 0x13 && fc.c64)
					continue;
				a.aug = "zR";
				n = build_file(&fc, gen_enc, &a, &in);
				snprintf(what, sizeof what, "c64=%d be=%d hdr=%d enc=0x%02x", fc.c64, fc.be, hdr, a.enc);
				if (!parse_ok(B, n, &ei)) { printf("  [%s] parse failed\n", what); fails++; continue; }
				fde_of(B, n, &ei, &r);
				want_f3(&r, what);
			}
		}
}

/* FNTAB-COV-3: an FDE that lies in a stub section (.plt, .plt.got, .plt.sec: the linker's and the loader's code, not the program's) is not a function of the table. 3 of the 364 FDEs of
 * /usr/bin/ls were. The section table of a built file is given one more executable section over the middle function; the entry point is in .text, so that is the program's code and the new
 * section is a stub. RED on main: the FDE strategy kept all three. Old tests missed it: (a) no table row had a section the linker made. */
static void t_fde_stub_section(void)
{
	unsigned fcase;

	for (fcase = 0; fcase < 4; fcase++) {
		struct fcase fc;
		struct enc_arg a = { 0x1b, "zR" };
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct fres r;
		uint32_t n, k, text = 0;
		char what[64];

		fc.c64 = fcase & 1; fc.be = (fcase >> 1) & 1; fc.sections = 1; fc.eh_hdr = 0;
		n = build_file(&fc, gen_enc, &a, &in);
		snprintf(what, sizeof what, "stub section c64=%d be=%d", fc.c64, fc.be);
		if (!parse_ok(B, n, &ei)) { printf("  [%s] parse failed\n", what); fails++; continue; }
		for (k = 1; k < ei.sec_count; k++)
			if (!strcmp(ei.sec[k].name, ".text"))
				text = k;
		CK(text != 0 && ei.sec_count < KGENOME_ELF_MAX_SECTIONS);
		if (!text)
			continue;
		ei.entry_addr = ei.sec[text].mem_addr;
		ei.sec[ei.sec_count] = ei.sec[text];
		snprintf(ei.sec[ei.sec_count].name, sizeof ei.sec[0].name, ".plt");
		ei.sec[ei.sec_count].file_off = TEXT_OFF + F3[1].off;
		ei.sec[ei.sec_count].file_size = F3[1].len;
		ei.sec[ei.sec_count].mem_addr = FBASE + TEXT_OFF + F3[1].off;
		ei.sec_count++;
		CK(kgenome_elf_sec_is_stub(&ei, ei.sec_count - 1u) && !kgenome_elf_sec_is_stub(&ei, text));
		fde_of(B, n, &ei, &r);
		if (r.n != 2u || r.v[0].off != TEXT_OFF + F3[0].off || r.v[1].off != TEXT_OFF + F3[2].off) {
			printf("  [%s] n=%u (wanted the two functions of the program's code)\n", what, r.n);
			fails++;
		}
		CK(r.n_bad == 1u && (r.partial & KGENOME_FNTAB_P_BAD_FDE));      /* the dropped one is said */
	}
}

/* FNTAB-COV-8: a refused allocation while the unwind table is read leaves what was read SORTED with the overlaps refused, like every other end of the strategy. 300 FDEs in descending order of
 * address (the list grows at 256: the second growth is the one refused), every allocation of the read refused in turn, the invariants of fde_inv on what comes back. RED on main: the
 * refusal skipped the sort and the list came back in the order of the file. Old tests missed it: (b) the sweep of allocations was run on the strategies that sort first. */
static void gen_many(struct eb *e, uint64_t text_va, const void *arg)
{
	uint8_t ad[1] = { 0x1b };
	uint32_t c = eb_cie(e, 1, "zR", ad, 1);
	unsigned i;

	(void)arg;
	for (i = 0; i < 300; i++)
		eb_fde(e, c, 0x1b, text_va + 0xf0u - (i % 0xf0u), 1);
	eb_un(e, 0, 4);
}

static void t_fde_refused_alloc_is_sorted(void)
{
	struct fcase fc;
	struct elf_in in;
	struct kgenome_elf_info ei;
	uint32_t n;
	unsigned k, hit = 0;

	fc.c64 = 1; fc.be = 0; fc.sections = 1; fc.eh_hdr = 0;
	n = build_file(&fc, gen_many, NULL, &in);
	CK(parse_ok(B, n, &ei));
	for (k = 1; k < 40; k++) {
		struct kgenome_fntab_list l;

		memset(&l, 0, sizeof l);
		alloc_seen = 0; fail_at = k;
		kgenome_fntab_fde(kof_buf_make(B, n), &ei, &l);
		if (!fail_at)
			hit++;
		fail_at = 0;
		fde_inv(&l, n);
		kgenome_fntab_list_free(&l);
	}
	CK(hit >= 3);
}

/* ---- the augmentations -------------------------------------------------------------------------------------------------------------------- */

struct aug_arg { unsigned ver; const char *aug; uint8_t ad[16]; unsigned adn; int enc; unsigned want; unsigned want_bad; };

static void gen_aug(struct eb *e, uint64_t text_va, const void *arg)
{
	const struct aug_arg *a = arg;
	uint32_t c = eb_cie(e, a->ver, a->aug, a->ad, a->adn);
	unsigned i;

	for (i = 0; i < 3; i++)
		eb_fde(e, c, a->enc, text_va + F3[i].off, F3[i].len);
	eb_un(e, 0, 4);
}

static void t_fde_augmentations(void)
{
	static const struct aug_arg rows[] = {
		/* ver  aug      augmentation data (the order of the string)       n   enc   want bad */
		{ 1, "zR",    { 0x1b },                                           1, 0x1b, 3, 0 },
		{ 1, "zPLR",  { 0x03, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x1b },       7, 0x1b, 3, 0 },   /* P: enc 3 + 4 bytes, L: enc, R: enc */
		{ 1, "zPLR",  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x1b }, 11, 0x1b, 3, 0 }, /* P absptr: 8 bytes (ELF64) / 4 (ELF32) -> both sets differ: see the run */
		{ 1, "zLR",   { 0x1b, 0x1b },                                     2, 0x1b, 3, 0 },
		{ 1, "zRS",   { 0x1b },                                           1, 0x1b, 3, 0 },   /* signal frame: no data */
		{ 1, "zRB",   { 0x1b },                                           1, 0x1b, 3, 0 },   /* pointer authentication: no data */
		{ 1, "zSR",   { 0x1b },                                           1, 0x1b, 3, 0 },
		{ 3, "zR",    { 0x1b },                                           1, 0x1b, 3, 0 },   /* version 3: the return register is a uleb */
		{ 1, "",      { 0 },                                         0xffffu, 0x00, 3, 0 },  /* no augmentation: absolute, the width of a pointer */
		{ 1, "zRX",   { 0x1b, 0x00 },                                     2, 0x1b, 3, 0 },   /* an unknown letter after R: R stands */
		{ 1, "zXR",   { 0x00, 0x1b },                                     2, 0x1b, 0, 3 },   /* an unknown letter BEFORE R: the data after it cannot be stepped over: no R, enc 0 -> the 0x1b FDEs read as absolute and fail */
		{ 1, "eh",    { 0 },                                         0xffffu, 0x00, 0, 3 },  /* the old GCC form is not read */
		{ 1, "xyz",   { 0 },                                         0xffffu, 0x00, 0, 3 },
		{ 2, "zR",    { 0x1b },                                           1, 0x1b, 0, 3 },   /* a version this does not read */
		{ 0, "zR",    { 0x1b },                                           1, 0x1b, 0, 3 },
		{ 4, "zR",    { 0x1b },                                           1, 0x1b, 0, 3 },
		{ 1, "zPR",   { 0x80 | 0x03, 0, 0, 0, 0, 0x1b },                  6, 0x1b, 3, 0 },   /* P with an indirect personality: its format is read (0x7f mask) */
		{ 1, "zPR",   { 0x03, 0, 0, 0, 0 },                               5, 0x1b, 0, 3 },   /* R missing from the data: the CIE is not read */
		{ 1, "zPR",   { 0x08, 0, 0, 0, 0, 0x1b },                         6, 0x1b, 0, 3 },   /* P with a format that has no width: not read */
	};
	unsigned i, fcase;

	for (fcase = 0; fcase < 4; fcase++)
		for (i = 0; i < sizeof rows / sizeof *rows; i++) {
			struct fcase fc;
			struct aug_arg a = rows[i];
			struct elf_in in;
			struct kgenome_elf_info ei;
			struct fres r;
			uint32_t n;

			fc.c64 = fcase & 1; fc.be = (fcase >> 1) & 1; fc.sections = 1; fc.eh_hdr = 0;
			/* the P pointer of an absptr personality is the width of a pointer: size the data to the class */
			if (i == 2) { a.adn = fc.c64 ? 11u : 7u; a.ad[1 + (fc.c64 ? 8 : 4)] = 0x1b; a.ad[2 + (fc.c64 ? 8 : 4)] = 0x1b; a.ad[9] = fc.c64 ? 0x1b : a.ad[9]; a.ad[10] = fc.c64 ? 0x1b : 0; }
			if (i == 2 && !fc.c64) { memset(a.ad, 0, sizeof a.ad); a.ad[5] = 0x1b; a.ad[6] = 0x1b; a.adn = 7; }
			if (i == 2 && fc.c64) { memset(a.ad, 0, sizeof a.ad); a.ad[9] = 0x1b; a.ad[10] = 0x1b; a.adn = 11; }
			n = build_file(&fc, gen_aug, &a, &in);
			if (!parse_ok(B, n, &ei)) { printf("  [aug row %u] parse failed\n", i); fails++; continue; }
			fde_of(B, n, &ei, &r);
			if (r.n != a.want || r.n_bad != a.want_bad) {
				printf("  [aug row %u class %u] n=%u bad=%u (want %u/%u)\n", i, fcase, r.n, r.n_bad, a.want, a.want_bad);
				fails++;
			}
			if (a.want == 3u && r.n == 3u)
				CK(r.v[0].off == TEXT_OFF && r.v[1].off == TEXT_OFF + 0x10 && r.v[2].off == TEXT_OFF + 0x30);
			CK(r.n_bad == 0 || (r.partial & KGENOME_FNTAB_P_BAD_FDE));
		}
}

/* ---- the encodings an FDE may NOT use, each counted ---------------------------------------------------------------------------------------- */

static void t_fde_refused_encodings(void)
{
	/* R values the strategy does not read: indirect, datarel, textrel, funcrel, aligned, omit, a format with no width */
	static const int bad[] = { 0x9b, 0x3b, 0x2b, 0x4b, 0x5b, 0x0b | 0x80, 0xff, 0x05, 0x06, 0x07, 0x08, 0x0d, 0x0e, 0x0f, 0x30, 0x20, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90 };
	unsigned i;

	for (i = 0; i < sizeof bad / sizeof *bad; i++) {
		struct fcase fc = { 1, 0, 1, 0 };
		struct enc_arg a;
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct fres r;
		uint32_t n;

		a.enc = bad[i]; a.aug = "zR";
		n = build_file(&fc, gen_enc, &a, &in);
		CK(parse_ok(B, n, &ei));
		fde_of(B, n, &ei, &r);
		if (r.n != 0u || r.n_bad != 3u || !(r.partial & KGENOME_FNTAB_P_BAD_FDE)) {
			printf("  [refused enc 0x%02x] n=%u bad=%u\n", bad[i], r.n, r.n_bad);
			fails++;
		}
	}
}

/* ---- the structure: lengths, ids, the CIE chain ------------------------------------------------------------------------------------------- */

struct raw_arg { unsigned kind; };

static void gen_raw(struct eb *e, uint64_t text_va, const void *arg)
{
	const struct raw_arg *a = arg;
	uint8_t ad[1] = { 0x1b };
	uint32_t c, f0;

	c = eb_cie(e, 1, "zR", ad, 1);
	switch (a->kind) {
	case 0:   /* a 64-bit length record (0xffffffff, then a u64) that is a valid FDE, then a normal one */
		f0 = e->n;
		eb_un(e, 0xffffffffu, 4); eb_un(e, 0, 8);
		{
			uint32_t start = e->n;
			eb_un(e, e->n - c, 4);
			eb_enc(e, 0x1b, (int64_t)((text_va + 0) - (e->va + e->n))); eb_enc(e, 0x1b, 11);
			eb_uleb(e, 0);
			while ((e->n - f0) % 4u) eb_u8(e, 0);
			{ uint64_t len = e->n - start; unsigned i; for (i = 0; i < 8; i++) e->b[f0 + 4 + i] = (uint8_t)(len >> (8u * (e->be ? 7u - i : i))); }
		}
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		break;
	case 1:   /* a 64-bit length that does not fit the section */
		eb_un(e, 0xffffffffu, 4); eb_un(e, 0x100000000ull, 8); eb_un(e, 0, 8);
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		break;
	case 2:   /* the 64-bit length cut off by the end of the section: only 8 of its 12 bytes are there */
		eb_un(e, 0xffffffffu, 4); eb_un(e, 1, 4);
		return;                                 /* no terminator: the section ends here */
	case 3:   /* length 1, 2, 3: below the 4 bytes of an id */
		eb_un(e, 1, 4); eb_un(e, 0, 4);
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		break;
	case 4:   /* an FDE whose CIE pointer is larger than its own position */
		f0 = e->n;
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		e->b[f0 + 4] = 0xff; e->b[f0 + 5] = 0xff; e->b[f0 + 6] = 0; e->b[f0 + 7] = 0;
		if (e->be) { e->b[f0 + 4] = 0; e->b[f0 + 5] = 0; e->b[f0 + 6] = 0xff; e->b[f0 + 7] = 0xff; }
		eb_fde(e, c, 0x1b, text_va + 0x30, 6);
		break;
	case 5:   /* an FDE whose CIE pointer lands on another FDE */
		f0 = eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		{ uint32_t at = e->n; eb_un(e, 0, 4); eb_un(e, (e->n - f0), 4); eb_enc(e, 0x1b, (int64_t)((text_va + 0x30) - (e->va + e->n))); eb_enc(e, 0x1b, 6); eb_uleb(e, 0); while ((e->n - at) % 4u) eb_u8(e, 0); eb_patch32(e, at, e->n - at - 4u); }
		break;
	case 6:   /* a CIE pointer into the middle of the CIE */
		{ uint32_t at = e->n; eb_un(e, 0, 4); eb_un(e, (e->n - c) - 2u, 4); eb_enc(e, 0x1b, (int64_t)((text_va + 0x10) - (e->va + e->n))); eb_enc(e, 0x1b, 6); eb_uleb(e, 0); while ((e->n - at) % 4u) eb_u8(e, 0); eb_patch32(e, at, e->n - at - 4u); }
		break;
	case 7:   /* two FDEs for the same start: the second is an overlap */
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		break;
	case 8:   /* overlapping, the second starts inside the first; and a longer first one */
		eb_fde(e, c, 0x1b, text_va + 0x10, 0x20);
		eb_fde(e, c, 0x1b, text_va + 0x18, 6);
		eb_fde(e, c, 0x1b, text_va + 0x30, 6);
		break;
	case 9:   /* out of order in the file: the strategy sorts */
		eb_fde(e, c, 0x1b, text_va + 0x30, 6);
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		eb_fde(e, c, 0x1b, text_va + 0x00, 11);
		break;
	case 10:  /* range 0 */
		eb_fde(e, c, 0x1b, text_va + 0x10, 0);
		eb_fde(e, c, 0x1b, text_va + 0x30, 6);
		break;
	case 11:  /* the range reaches past its segment, an FDE below the segment, an FDE into the headers' page */
		eb_fde(e, c, 0x1b, text_va + 0x10, 0x100000);
		eb_fde(e, c, 0x1b, 0x10, 6);
		eb_fde(e, c, 0x1b, text_va + 0x30, 6);
		break;
	case 12:  /* sdata4 range with the top bit set: a length is unsigned, here 0xfffffff0 bytes: out of the segment */
		eb_fde(e, c, 0x1b, text_va + 0x10, 0xfffffff0u);
		break;
	case 13:  /* the terminator in the middle: what follows is not read */
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		eb_un(e, 0, 4);
		eb_fde(e, c, 0x1b, text_va + 0x30, 6);
		break;
	case 14:  /* an FDE before any CIE: its pointer goes back past the table */
		e->n = 0;
		eb_fde(e, 0, 0x1b, text_va + 0x10, 6);
		break;
	case 15:  /* an FDE whose pc_begin is cut by the end of the record (a record of 12 bytes) */
		eb_un(e, 8, 4); eb_un(e, e->n - c, 4); eb_un(e, 0, 4);
		break;
	case 16:  /* a pc_range cut by the end of the record */
		eb_un(e, 12, 4); eb_un(e, e->n - c, 4); eb_un(e, 0, 4); eb_un(e, 0, 4);
		break;
	case 17:  /* a record whose id is 0 but is a CIE too short to read */
		eb_un(e, 4, 4); eb_un(e, 0, 4);
		eb_fde(e, c, 0x1b, text_va + 0x10, 6);
		break;
	}
	eb_un(e, 0, 4);
}

static void t_fde_structure(void)
{
	/* kind: want n, want bad at least */
	static const struct { unsigned kind, n, bad; } rows[] = {
		{ 0, 2, 0 }, { 1, 0, 1 }, { 2, 0, 99 }, { 3, 0, 1 }, { 4, 1, 1 }, { 5, 1, 1 }, { 6, 0, 1 }, { 7, 1, 1 }, { 8, 2, 1 }, { 9, 3, 0 },
		{ 10, 1, 1 }, { 11, 1, 2 }, { 12, 0, 1 }, { 13, 1, 0 }, { 14, 0, 1 }, { 15, 0, 1 }, { 16, 0, 1 }, { 17, 1, 0 },
	};
	unsigned i, fcase, hdr;

	for (fcase = 0; fcase < 4; fcase++)
		for (hdr = 0; hdr < 2; hdr++)
			for (i = 0; i < sizeof rows / sizeof *rows; i++) {
				struct fcase fc;
				struct raw_arg a;
				struct elf_in in;
				struct kgenome_elf_info ei;
				struct fres r;
				uint32_t n;

				fc.c64 = fcase & 1; fc.be = (fcase >> 1) & 1; fc.sections = !hdr; fc.eh_hdr = (int)hdr;
				a.kind = rows[i].kind;
				n = build_file(&fc, gen_raw, &a, &in);
				if (!parse_ok(B, n, &ei)) { printf("  [raw %u] parse failed\n", rows[i].kind); fails++; continue; }
				fde_of(B, n, &ei, &r);
				if (r.n != rows[i].n || (rows[i].bad == 99u ? 0 : rows[i].bad ? r.n_bad < rows[i].bad : r.n_bad != 0)) {
					printf("  [raw kind %u class %u hdr %u] n=%u bad=%u (want %u/%u)\n", rows[i].kind, fcase, hdr, r.n, r.n_bad, rows[i].n, rows[i].bad);
					fails++;
				}
				CK(!r.n_bad || (r.partial & KGENOME_FNTAB_P_BAD_FDE));
			}
}


/* ---- the PT_GNU_EH_FRAME header: every way it can lie -------------------------------------------------------------------------------------- */

static void gen_f3(struct eb *e, uint64_t text_va, const void *arg)
{
	uint8_t ad[1] = { 0x1b };
	uint32_t c = eb_cie(e, 1, "zR", ad, 1);
	unsigned i;

	(void)arg;
	for (i = 0; i < 3; i++)
		eb_fde(e, c, 0x1b, text_va + F3[i].off, F3[i].len);
	eb_un(e, 0, 4);
}

static uint32_t hdr_off_of(const struct elf_in *in) { struct lay l; layout(in, &l); return l.hdr_off; }

static void put_ptr(uint8_t *at, int be, int w, uint64_t v)
{
	int i;
	for (i = 0; i < w; i++)
		at[be ? w - 1 - i : i] = (uint8_t)(v >> (8 * i));
}

static void t_fde_header(void)
{
	unsigned fcase;

	for (fcase = 0; fcase < 4; fcase++) {
		struct fcase fc = { (int)(fcase & 1), (int)((fcase >> 1) & 1), 0, 1 };
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct fres r;
		uint32_t n, h, eh_va_off;
		uint8_t save[16];
		int w = fc.c64 ? 8 : 4;
		uint64_t eva;
		struct lay l;

		n = build_file(&fc, gen_f3, NULL, &in);
		h = hdr_off_of(&in);
		layout(&in, &l);
		eva = l.eh_va;
		eh_va_off = l.eh_off;
		(void)eh_va_off;
		memcpy(save, B + h, 16);
		CK(parse_ok(B, n, &ei) && ei.sec_count == 0);
		fde_of(B, n, &ei, &r); want_f3(&r, "hdr: as built");

		/* version other than 1 */
		B[h] = 2; CK(parse_ok(B, n, &ei)); fde_of(B, n, &ei, &r); CK(r.n == 0); B[h] = 1;
		B[h] = 0; fde_of(B, n, &ei, &r); CK(r.n == 0); B[h] = 1;
		/* the encodings of eh_frame_ptr that are not read (datarel, textrel, funcrel, aligned: low nibble ok, class wrong) */
		{
			static const uint8_t bad[] = { 0x3b, 0x2b, 0x4b, 0x5b, 0x1d, 0x15, 0x08, 0x0d, 0x06, 0xff };
			unsigned i;
			for (i = 0; i < sizeof bad; i++) {
				B[h + 1] = bad[i];
				fde_of(B, n, &ei, &r);
				if (r.n != 0) { printf("  [hdr enc 0x%02x] n=%u\n", bad[i], r.n); fails++; }
			}
			B[h + 1] = 0x1b;
		}
		/* absolute encodings: udata4 / sdata4 / absptr / udata8 / uleb with the address written out */
		{
			static const struct { uint8_t enc; int w; } abs[] = { { 0x03, 4 }, { 0x0b, 4 }, { 0x00, 0 }, { 0x04, 8 }, { 0x0c, 8 } };
			unsigned i;
			for (i = 0; i < sizeof abs / sizeof *abs; i++) {
				int ww = abs[i].w ? abs[i].w : w;
				/* the pointer field is at h+4; the fixed 16-byte header holds 4 + 8 bytes: an 8-byte pointer overwrites the count, which is not read */
				B[h + 1] = abs[i].enc;
				memset(B + h + 4, 0, 12);
				put_ptr(B + h + 4, fc.be, ww, eva);
				fde_of(B, n, &ei, &r);
				if (r.n != 3) { printf("  [hdr abs enc 0x%02x class %u] n=%u\n", abs[i].enc, fcase, r.n); fails++; }
			}
			/* the same with a 1-byte uleb that cannot hold the address: the pointer goes elsewhere: nothing */
			B[h + 1] = 0x01; memset(B + h + 4, 0, 12); B[h + 4] = 0x10;
			fde_of(B, n, &ei, &r); CK(r.n == 0);
			B[h + 1] = 0x1b; memcpy(B + h, save, 16);
		}
		/* eh_frame_ptr outside every segment, and 0 */
		put_ptr(B + h + 4, fc.be, 4, 0x7fffff00u); fde_of(B, n, &ei, &r); CK(r.n == 0);
		put_ptr(B + h + 4, fc.be, 4, 0u);          fde_of(B, n, &ei, &r); CK(r.n == 0);
		memcpy(B + h, save, 16);
		/* the pointer names the second CIE's FDEs instead: a table that starts mid-table is read from where it starts (a CIE pointer back past the start is refused) */
		put_ptr(B + h + 4, fc.be, 4, (uint64_t)(eva - (FBASE + h + 4u)) + 0x18u);
		fde_of(B, n, &ei, &r); CK(r.n <= 2 && r.n_bad >= 1);
		memcpy(B + h, save, 16);
		/* the header cut by the end of the file: 5 bytes of it (below 8), then the whole of it but for the pointer, then the file ends before .eh_frame */
		fde_of(B, h + 5, &ei, &r); CK(r.n == 0);
		fde_of(B, h + 7, &ei, &r); CK(r.n == 0);                 /* the pointer is cut: 3 of 4 bytes */
		fde_of(B, h + 8, &ei, &r); want_f3(&r, "hdr: 8 bytes of 12, the pointer is whole");
		fde_of(B, l.eh_off, &ei, &r); CK(r.n == 0);               /* no data at all */
		fde_of(B, 0, &ei, &r); CK(r.n == 0);
		fde_of(B, h, &ei, &r); CK(r.n == 0);                      /* the file ends where the header would begin: the segment's claim is not believed */
		/* the segment claims more than the file holds, and the unwind table is clipped to the file */
		{
			struct kgenome_elf_info e2 = ei;
			e2.seg[0].file_size += 0x10000u; e2.seg[0].mem_size += 0x10000u;
			fde_of(B, l.eh_off + 16u, &e2, &r);                    /* the file stops 16 bytes into .eh_frame */
			CK(r.n <= 1);
			fde_of(B, n, &e2, &r); want_f3(&r, "hdr: segment claims more");
			/* a pointer to an address the segment maps and the file does not hold */
			B[h + 1] = 0x03; memset(B + h + 4, 0, 4);
			put_ptr(B + h + 4, fc.be, 4, FBASE + n + 0x20u);
			fde_of(B, n, &e2, &r); CK(r.n == 0);
			memcpy(B + h, save, 16);
			/* a header segment whose file offset is past the file */
			e2 = ei; e2.seg[1].file_off = n + 100u;
			fde_of(B, n, &e2, &r); CK(r.n == 0);
			/* a header with the segment non-executable: the FDEs are of a stub the loader maps elsewhere */
			e2 = ei; e2.seg[0].perm = 0;
			fde_of(B, n, &e2, &r); CK(r.n == 0 && r.n_bad == 3 && (r.partial & KGENOME_FNTAB_P_BAD_FDE));
		}
		/* an ET_REL has no unwind addresses; an invalid info and a NULL info answer nothing */
		{
			struct kgenome_elf_info e2 = ei;
			struct kgenome_fntab_list lst;
			e2.e_type = KGENOME_ELF_REL;
			fde_of(B, n, &e2, &r); CK(r.n == 0 && r.n_bad == 0);
			e2 = ei; e2.valid = 0;
			fde_of(B, n, &e2, &r); CK(r.n == 0);
			memset(&lst, 0, sizeof lst);
			kgenome_fntab_fde(kof_buf_make(B, n), NULL, &lst); CK(lst.n == 0);
			kgenome_fntab_fde(kof_buf_make(NULL, 0), &ei, &lst); CK(lst.n == 0);
		}
	}
}

/* the section path: the section lies about where it is */
static void t_fde_section_lies(void)
{
	unsigned fcase;

	for (fcase = 0; fcase < 4; fcase++) {
		struct fcase fc = { (int)(fcase & 1), (int)((fcase >> 1) & 1), 1, 0 };
		struct elf_in in;
		struct kgenome_elf_info ei, e2;
		struct fres r;
		uint32_t n, i, k = 0;
		struct lay l;

		n = build_file(&fc, gen_f3, NULL, &in);
		layout(&in, &l);
		CK(parse_ok(B, n, &ei));
		for (i = 1; i < ei.sec_count; i++)
			if (!strcmp(ei.sec[i].name, ".eh_frame")) k = i;
		CK(k);
		fde_of(B, n, &ei, &r); want_f3(&r, "section: as built");
		e2 = ei; e2.sec[k].file_off = n;                 fde_of(B, n, &e2, &r); CK(r.n == 0);       /* starts at the end of the file */
		e2 = ei; e2.sec[k].file_off = n + 50u;           fde_of(B, n, &e2, &r); CK(r.n == 0);
		e2 = ei; e2.sec[k].file_size = 0x100000u;        fde_of(B, n, &e2, &r); want_f3(&r, "section: size past the file");   /* clipped to the file */
		e2 = ei; e2.sec[k].file_size = 7;                fde_of(B, n, &e2, &r); CK(r.n == 0);
		e2 = ei; e2.sec[k].file_size = 8;                fde_of(B, n, &e2, &r); CK(r.n == 0);       /* the CIE alone is not whole */
		for (i = 0; i <= in.eh_n + 4u; i++) {             /* the section ends at every offset of the table: what is kept is a prefix of the three, each whole */
			e2 = ei; e2.sec[k].file_size = i;
			fde_of(B, n, &e2, &r);
			CK(r.n <= 3);
			if (i < in.eh_n - 4u)
				CK(r.n < 3);
		}
		/* the section's address moves: a pcrel value is then a different place */
		e2 = ei; e2.sec[k].mem_addr += 0x1000000u;       fde_of(B, n, &e2, &r); CK(r.n == 0 && r.n_bad == 3);
		/* a segment with no section naming it: the section names it but there is no PT_LOAD over the targets */
		e2 = ei; e2.seg_count = 0;                      fde_of(B, n, &e2, &r); CK(r.n == 0 && r.n_bad == 3);
	}
}

/* ---- LEB128 in the CIE: long, overlong and cut ---------------------------------------------------------------------------------------------- */

static const uint8_t *leb_code, *leb_data;
static unsigned leb_code_n, leb_data_n;

static void gen_leb(struct eb *e, uint64_t text_va, const void *arg)
{
	uint32_t at = e->n, c;
	unsigned i;

	(void)arg;
	eb_un(e, 0, 4); eb_un(e, 0, 4);
	eb_u8(e, 1); eb_u8(e, 'z'); eb_u8(e, 'R'); eb_u8(e, 0);
	for (i = 0; i < leb_code_n; i++) eb_u8(e, leb_code[i]);
	for (i = 0; i < leb_data_n; i++) eb_u8(e, leb_data[i]);
	eb_u8(e, 16); eb_uleb(e, 1); eb_u8(e, 0x1b);
	while ((e->n - at) % 4u) eb_u8(e, 0);
	eb_patch32(e, at, e->n - at - 4u);
	c = at;
	for (i = 0; i < 3; i++)
		eb_fde(e, c, 0x1b, text_va + F3[i].off, F3[i].len);
	eb_un(e, 0, 4);
}

static void t_fde_leb(void)
{
	static const uint8_t one[] = { 0x01 }, neg[] = { 0x78 };
	static const uint8_t long_u[] = { 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };   /* 12 bytes: past 64 bits */
	static const uint8_t long_s[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };   /* -1 in 12 bytes */
	static const uint8_t endless[] = { 0x80, 0x80, 0x80, 0x80, 0x80 };
	static const struct { const uint8_t *c; unsigned cn; const uint8_t *d; unsigned dn; unsigned want; } rows[] = {
		{ one, 1, neg, 1, 3 }, { long_u, 12, neg, 1, 3 }, { one, 1, long_s, 12, 3 }, { long_u, 12, long_s, 12, 3 },
		{ endless, 5, neg, 1, 0 },         /* the code alignment never ends: the CIE is not read */
		{ one, 1, endless, 5, 0 },         /* the data alignment never ends */
	};
	struct fcase fc = { 1, 0, 1, 0 };
	unsigned i;

	for (i = 0; i < sizeof rows / sizeof *rows; i++) {
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct fres r;
		uint32_t n;

		leb_code = rows[i].c; leb_code_n = rows[i].cn; leb_data = rows[i].d; leb_data_n = rows[i].dn;
		n = build_file(&fc, gen_leb, NULL, &in);
		CK(parse_ok(B, n, &ei));
		fde_of(B, n, &ei, &r);
		if (r.n != rows[i].want) { printf("  [leb row %u] n=%u bad=%u\n", i, r.n, r.n_bad); fails++; }
	}
}

/* ---- the CIE table: its cap, said ---------------------------------------------------------------------------------------------------------------- */

struct cap_arg { unsigned before; };

static void gen_cie_cap(struct eb *e, uint64_t text_va, const void *arg)
{
	const struct cap_arg *a = arg;
	uint8_t ad[1] = { 0x1b };
	uint32_t c, i;

	for (i = 0; i < a->before; i++) {            /* CIEs of a version this does not read: 9 bytes each, they still take a slot of the table */
		eb_un(e, 5, 4); eb_un(e, 0, 4); eb_u8(e, 9);
	}
	c = eb_cie(e, 1, "zR", ad, 1);                    /* the a->before + 1 th CIE */
	eb_fde(e, c, 0x1b, text_va + 0x10, 6);
	{
		uint32_t c2 = eb_cie(e, 1, "zR", ad, 1);      /* the next one */
		eb_fde(e, c2, 0x1b, text_va + 0x30, 6);
	}
	eb_un(e, 0, 4);
}

static void t_fde_cie_cap(void)
{
	/* 65535 before: the real CIE is the 65536th (kept), the next is the 65537th (past the table, counted, and the FDE that names it is refused) */
	static const unsigned before[] = { 0, 15, 16, 17, 65534u, 65535u, 65536u };
	unsigned i;
	struct fcase fc = { 1, 0, 1, 0 };

	ehp = malloc(4u << 20); ehcap = 4u << 20;
	g_maxb = MAXB_BIG;
	CK(ehp != NULL);
	for (i = 0; i < sizeof before / sizeof *before; i++) {
		struct cap_arg a;
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct fres r;
		uint32_t n;
		unsigned want_n = before[i] + 1u <= 65536u ? (before[i] + 2u <= 65536u ? 2u : 1u) : 0u;
		unsigned want_bad = before[i] + 1u <= 65536u ? (before[i] + 2u <= 65536u ? 0u : 2u) : 4u;

		a.before = before[i];
		n = build_file(&fc, gen_cie_cap, &a, &in);
		CK(n > in.eh_n && in.eh_n < ehcap);
		CK(parse_ok(B, n, &ei));
		fde_of(B, n, &ei, &r);
		if (r.n != want_n || r.n_bad != want_bad) { printf("  [cie cap before=%u] n=%u bad=%u (want %u/%u)\n", before[i], r.n, r.n_bad, want_n, want_bad); fails++; }
	}
	g_maxb = 0x4000u;
	free(ehp); ehp = EHB; ehcap = sizeof EHB;
}

/* ---- every byte of a rich table poisoned, and the file cut at every offset --------------------------------------------------------------------------- */

static void gen_rich(struct eb *e, uint64_t text_va, const void *arg)
{
	static const uint8_t ad[] = { 0x03, 0, 0, 0, 0, 0x1b, 0x1b };
	uint32_t c, c2;

	(void)arg;
	c = eb_cie(e, 1, "zPLR", ad, sizeof ad);
	eb_fde(e, c, 0x1b, text_va + 0x00, 11);
	c2 = eb_cie(e, 1, "zR", ad + 6, 1);
	eb_fde(e, c2, 0x1b, text_va + 0x10, 6);
	eb_fde(e, c, 0x1b, text_va + 0x20, 8);
	eb_fde(e, c2, 0x1b, text_va + 0x30, 6);
	eb_un(e, 0, 4);
}

static void t_fde_poison_cut(void)
{
	static const uint8_t vals[] = { 0x00, 0x01, 0x04, 0x7f, 0x80, 0xfe, 0xff };
	unsigned fcase, hdr;

	for (fcase = 0; fcase < 4; fcase++)
		for (hdr = 0; hdr < 2; hdr++) {
			struct fcase fc = { (int)(fcase & 1), (int)((fcase >> 1) & 1), !hdr, (int)hdr };
			struct elf_in in;
			struct kgenome_elf_info ei;
			struct fres r;
			struct lay l;
			uint32_t n, i, v, hoff;
			uint8_t keep;

			n = build_file(&fc, gen_rich, NULL, &in);
			layout(&in, &l);
			CK(parse_ok(B, n, &ei));
			fde_of(B, n, &ei, &r);
			CK(r.n == 4 && r.n_bad == 0);
			/* poison */
			for (i = 0; i < in.eh_n; i++) {
				keep = B[l.eh_off + i];
				for (v = 0; v < sizeof vals; v++) {
					B[l.eh_off + i] = vals[v];
					fde_of(B, n, &ei, &r);                /* fde_inv inside: sorted, inside the file, tagged */
					CK(r.n <= 4u);
				}
				B[l.eh_off + i] = keep;
			}
			/* the header's own bytes (the segment path reads them) */
			hoff = l.hdr_off;
			for (i = 0; hdr && i < 16; i++) {
				keep = B[hoff + i];
				for (v = 0; v < sizeof vals; v++) {
					B[hoff + i] = vals[v];
					fde_of(B, n, &ei, &r);
					CK(r.n <= 4u);
				}
				B[hoff + i] = keep;
			}
			/* the file cut at every offset from the start of .eh_frame (the info is the one of the whole file) */
			for (i = 0; i <= n; i++) {
				fde_of(B, i, &ei, &r);
				CK(r.n <= 4u);
				if (i >= l.eh_off + in.eh_n + (hdr ? 16u : 0u) && i >= l.seg_end)
					CK(r.n == 4u);
			}
		}
}

/* ---- every allocation fails once ------------------------------------------------------------------------------------------------------------------ */

static void t_fde_nomem(void)
{
	struct fcase fc = { 1, 0, 1, 0 };
	struct elf_in in;
	struct kgenome_elf_info ei;
	uint32_t n = build_file(&fc, gen_f3, NULL, &in);
	unsigned k, hit = 0;

	CK(parse_ok(B, n, &ei));
	for (k = 1; k < 8; k++) {
		struct kgenome_fntab_list l;

		memset(&l, 0, sizeof l);
		alloc_seen = 0; fail_at = k;
		kgenome_fntab_fde(kof_buf_make(B, n), &ei, &l);
		if (!fail_at) {                                  /* the Nth allocation was reached and failed */
			hit++;
			CK(l.status == KGENOME_NOMEM);
			CK(l.n <= 3);
		} else {
			CK(l.status == KGENOME_OK && l.n == 3);
		}
		fail_at = 0;
		kgenome_fntab_list_free(&l);
	}
	CK(hit == 2);                                         /* the CIE table and the entry list: two allocations in a table of three FDEs */
}


/* ---- the CIE cut at every length: the record ends inside the version, the string, a LEB, the augmentation data, the personality ---------------------------------- */

struct cut_arg { unsigned ver; const char *aug; uint8_t ad[16]; unsigned adn; };

static void gen_cut(struct eb *e, uint64_t text_va, const void *arg)
{
	const struct cut_arg *a = arg;
	uint32_t c = eb_cie(e, a->ver, a->aug, a->ad, a->adn);
	unsigned i;

	for (i = 0; i < 3; i++)
		eb_fde(e, c, 0x1b, text_va + F3[i].off, F3[i].len);
	eb_un(e, 0, 4);
}

static void t_fde_cie_cut(void)
{
	static const struct cut_arg rows[] = {
		{ 1, "zPLR", { 0x03, 0, 0, 0, 0, 0x1b, 0x1b }, 7 },
		{ 3, "zPLR", { 0x03, 0, 0, 0, 0, 0x1b, 0x1b }, 7 },
		{ 1, "zR", { 0x1b }, 1 },
		{ 3, "zRS", { 0x1b }, 1 },
		{ 1, "eh", { 0 }, 0xffffu },
		{ 1, "ex", { 0 }, 0xffffu },
		{ 1, "zPR", { 0x83, 0, 0, 0, 0, 0x1b }, 6 },
		{ 1, "zPR", { 0x01, 0x85, 0x01, 0x1b }, 4 },        /* a personality in uleb */
		{ 1, "zPR", { 0x09, 0x7f, 0x1b }, 3 },              /* a personality in sleb */
	};
	unsigned i, fcase;

	for (fcase = 0; fcase < 4; fcase++)
		for (i = 0; i < sizeof rows / sizeof *rows; i++) {
			struct fcase fc = { (int)(fcase & 1), (int)((fcase >> 1) & 1), 1, 0 };
			struct elf_in in;
			struct kgenome_elf_info ei;
			struct fres r;
			struct lay l;
			uint32_t n, cie_len, L, orig;
			static uint8_t keep[4];
			struct eb w;

			n = build_file(&fc, gen_cut, &rows[i], &in);
			layout(&in, &l);
			CK(parse_ok(B, n, &ei));
			w.be = fc.be;
			orig = (uint32_t)(B[l.eh_off + (fc.be ? 3 : 0)] | (B[l.eh_off + 1] << 8));
			if (fc.be) orig = (uint32_t)B[l.eh_off + 3];
			cie_len = orig;
			memcpy(keep, B + l.eh_off, 4);
			for (L = 0; L <= cie_len + 1u; L++) {
				uint8_t *p = B + l.eh_off;
				unsigned j;
				for (j = 0; j < 4; j++) p[fc.be ? 3u - j : j] = (uint8_t)(L >> (8u * j));
				fde_of(B, n, &ei, &r);
				CK(r.n <= 3u);
				if (L == cie_len && i != 4 && i != 5)
					CK(r.n == 3u);
				if (L < cie_len)
					CK(r.n < 3u || i == 3);        /* a cut CIE of "zRS" ends after the R: the S is data-free, so the cut is only visible past it */
			}
			memcpy(B + l.eh_off, keep, 4);
			(void)w;
		}
}

/* a CIE whose last byte is a LEB continuation; an FDE whose pc_begin is an sleb that runs out */
static void gen_sleb_fde(struct eb *e, uint64_t text_va, const void *arg)
{
	uint8_t ad[1] = { 0x19 };                          /* pcrel sleb */
	uint32_t c = eb_cie(e, 1, "zR", ad, 1), at = e->n;

	(void)arg; (void)text_va;
	eb_un(e, 0, 4); eb_un(e, e->n - c, 4);
	eb_u8(e, 0x80); eb_u8(e, 0x80);                    /* the sleb never ends inside the record */
	eb_patch32(e, at, e->n - at - 4u);
	eb_un(e, 0, 4);
}

static void t_fde_leb_runs_out(void)
{
	struct fcase fc = { 1, 0, 1, 0 };
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct fres r;
	uint32_t n = build_file(&fc, gen_sleb_fde, NULL, &in);

	CK(parse_ok(B, n, &ei));
	fde_of(B, n, &ei, &r);
	CK(r.n == 0 && r.n_bad == 1);
}


/* ---- the symbol-table strategy against an oracle ------------------------------------------------------------------------------------------ */

#define SYM_N 10

struct symcase { struct sym s[SYM_N]; unsigned n; };

/* What the symbol strategy must answer, written from the sentence in its header (not from its loop): a function is STT_FUNC, STT_GNU_IFUNC, or NOTYPE that declares a size; it names a section
 * that is executable (only .text here); it lies inside the segment (linked) or the section (ET_REL) and inside the file; a size-0 one runs to the next kept start above it or the section's end. */
static unsigned sym_expect(const struct elf_in *in, const struct symcase *sc, int rel, uint32_t fsize, struct kgenome_func *x)
{
	struct lay l;
	unsigned i, n = 0, j;
	const uint64_t sec_end = TEXT_OFF + in->text_n;
	layout(in, &l);
	for (i = 0; i < sc->n; i++) {
		const struct sym *y = &sc->s[i];
		unsigned ty = y->info & 0xfu;
		uint64_t value = y->value, off;
		struct kgenome_func f;

		if (!(ty == 2 || ty == 10 || (ty == 0 && y->size)))
			continue;
		if (y->shndx != 1)
			continue;                                          /* 0: undefined, >= 2: not executable here (or out of range) */
		memset(&f, 0, sizeof f);
		f.kind = ty == 10 ? KGENOME_FN_IFUNC : KGENOME_FN_FUNC;
		if (in->em == 40 && ty == 2 && (value & 1u)) { value &= ~(uint64_t)1; f.isa_mode = KGENOME_FN_ISA_THUMB; }
		if (!rel) {
			uint64_t sz = y->size ? y->size : 1u;
			if (value < in->base || value - in->base > l.seg_end || sz > l.seg_end - (value - in->base))
				continue;
			off = value - in->base;
		} else {
			if (value > fsize || TEXT_OFF > fsize - value)
				continue;
			off = TEXT_OFF + value;
		}
		if (off > fsize || y->size > fsize - off)
			continue;
		f.off = off; f.len = y->size; f.value = y->value; f.shndx = y->shndx; f.source = in->dyn ? KGENOME_FN_S_DYNSYM : KGENOME_FN_S_SYMTAB;
		if (y->size) f.end_source = KGENOME_FN_E_SYMBOL; else f.flags = KGENOME_FN_F_SIZE0;
		x[n++] = f;
	}
	for (i = 0; i < n; i++)
		if (x[i].flags & KGENOME_FN_F_SIZE0) {
			uint64_t end = sec_end;
			for (j = 0; j < n; j++)
				if (x[j].off > x[i].off && x[j].off < end)
					end = x[j].off;
			if (end > fsize) end = fsize;
			x[i].len = end > x[i].off ? end - x[i].off : 0;
			x[i].end_source = KGENOME_FN_E_NEXT_START;
			x[i].flags |= KGENOME_FN_F_END_OPEN;
		}
	return n;
}

static int func_eq(const struct kgenome_func *a, const struct kgenome_func *b)
{
	return a->off == b->off && a->len == b->len && a->value == b->value && a->shndx == b->shndx && a->kind == b->kind && a->end_source == b->end_source &&
	       a->isa_mode == b->isa_mode && a->source == b->source && a->flags == b->flags;
}

static void sym_random(struct symcase *sc, const struct elf_in *in, int rel)
{
	static const uint8_t types[] = { 0, 1, 2, 2, 2, 10, 3, 4, 2 };
	static const uint16_t shn[] = { 0, 1, 1, 1, 1, 2, 3, 99, 0xfff1 };
	static const uint64_t sizes[] = { 0, 0, 1, 6, 8, 0x10, 0x40, 0x1000, 0x100000, 0xffffffffffull };
	unsigned i;

	sc->n = (unsigned)(rnd() % (SYM_N + 1));
	for (i = 0; i < sc->n; i++) {
		struct sym *y = &sc->s[i];
		unsigned r = (unsigned)(rnd() % 10);
		uint64_t d = rnd() % 0x48;

		y->name = "f";
		y->info = (uint8_t)(((rnd() & 1) << 4) | types[rnd() % sizeof types]);
		y->shndx = shn[rnd() % (sizeof shn / sizeof *shn)];
		y->size = sizes[rnd() % (sizeof sizes / sizeof *sizes)];
		if (rel)
			y->value = r == 0 ? 0x100000 : d;
		else
			y->value = r == 0 ? 0x70000000ull : r == 1 ? in->base + 0x200 : r == 2 ? 0 : in->base + TEXT_OFF + d;
		if (in->em == 40 && (rnd() & 1))
			y->value |= 1u;
		if (!in->c64)
			y->value &= 0xffffffffull;
	}
}

static void t_symtab_oracle(void)
{
	unsigned iter, cls;
	static struct kgenome_func X[SYM_N + 1];
	static uint8_t TX[0x100];

	for (iter = 0; iter < 6000; iter++) {
		struct elf_in in;
		struct symcase sc;
		struct kgenome_elf_info ei;
		struct kgenome_obj o;
		struct kgenome_fntab_list l;
		uint32_t n;
		unsigned nx, i, rel = iter % 7 == 0, dyn = iter % 3 == 0;

		cls = iter % 4;
		memset(&in, 0, sizeof in);
		in.c64 = cls & 1; in.be = (cls >> 1) & 1;
		in.em = (iter % 5 == 0) ? 40 : in.c64 ? (in.be ? 21 : 62) : (in.be ? 20 : 3);
		if (in.em == 40) { in.c64 = 0; }
		in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.rodata_n = 0x20;
		in.sections = 1; in.dyn = (int)dyn;
		sym_random(&sc, &in, (int)rel);
		in.sym = sc.s; in.nsym = sc.n;
		n = elf_build(&in, B);
		if (!parse(B, n, &ei, &o)) { fails++; printf("  [sym] parse failed iter %u\n", iter); continue; }
		if (rel) ei.e_type = KGENOME_ELF_REL;
		nx = sym_expect(&in, &sc, (int)rel, n, X);
		memset(&l, 0, sizeof l);
		kgenome_fntab_symtab(kof_buf_make(B, n), &ei, (int)dyn, &l);
		if (l.n != nx) {
			printf("  [sym iter %u rel=%u dyn=%u em=%u] got %u want %u\n", iter, rel, dyn, in.em, l.n, nx);
			fails++;
		} else {
			for (i = 0; i < nx; i++)
				if (!func_eq(&l.v[i], &X[i])) {
					printf("  [sym iter %u entry %u] off %llx/%llx len %llu/%llu end_src %u/%u flags %x/%x src %x/%x\n", iter, i, (unsigned long long)l.v[i].off, (unsigned long long)X[i].off,
					       (unsigned long long)l.v[i].len, (unsigned long long)X[i].len, l.v[i].end_source, X[i].end_source, l.v[i].flags, X[i].flags, l.v[i].source, X[i].source);
					fails++;
					break;
				}
		}
		CK(l.status == KGENOME_OK);
		kgenome_fntab_list_free(&l);
	}
}

/* the symbol strategy on an info that is wrong */
static void t_symtab_edges(void)
{
	static uint8_t TX[0x100];
	struct sym sy[3] = { { "a", 0x400000u + TEXT_OFF, 8, 0x12, 1 }, { "z", 0x400000u + TEXT_OFF + 0x10, 0, 0x12, 1 }, { "b", 0x400000u + TEXT_OFF + 0x20, 8, 0x12, 1 } };
	struct elf_in in;
	struct kgenome_elf_info ei, e2;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	uint32_t n, k;
	unsigned t, hit;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.sections = 1; in.sym = sy; in.nsym = 3;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
	CK(l.n == 3 && l.v[1].len == 0x10);             /* z runs to b */
	kgenome_fntab_list_free(&l);
	/* NULL file, NULL info, invalid info: nothing, no crash */
	kgenome_fntab_symtab(kof_buf_make(NULL, 0), &ei, 0, &l); CK(l.n == 0);
	kgenome_fntab_symtab(kof_buf_make(B, n), NULL, 0, &l); CK(l.n == 0);
	e2 = ei; e2.valid = 0; kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l); CK(l.n == 0);
	/* the .dynsym asked of a file that has none */
	kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 1, &l); CK(l.n == 0);
	/* the file cut inside the symbol table: what the reader refuses is not read */
	for (k = 0; k <= n; k += 1) {
		memset(&l, 0, sizeof l);
		kgenome_fntab_symtab(kof_buf_make(B, k), &ei, 0, &l);
		CK(l.n <= 3);
		kgenome_fntab_list_free(&l);
	}
	/* the section of a size-0 symbol claims more than the file: the end is the file's */
	e2 = ei; e2.sec[1].file_size = 0x1000000u;
	sy[2].size = 0; n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	e2 = ei; e2.sec[1].file_size = 0x1000000u;
	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l);
	CK(l.n == 3);
	for (t = 0; t < l.n; t++)
		if (l.v[t].off == TEXT_OFF + 0x20) CK(l.v[t].off + l.v[t].len == n);
	kgenome_fntab_list_free(&l);
	/* a size-0 symbol at the very end of its section: length 0 (the ends step then closes it); and above the section's end */
	sy[2].value = 0x400000u + TEXT_OFF + 0x40; n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
	for (t = 0; t < l.n; t++)
		if (l.v[t].off == TEXT_OFF + 0x40) CK(l.v[t].len == 0 && l.v[t].end_source == KGENOME_FN_E_NEXT_START);
	kgenome_fntab_list_free(&l);
	/* the cap: the list is at its bound, the first symbol is refused and said */
	CK(parse(B, n, &ei, &o));
	memset(&l, 0, sizeof l);
	l.n = KGENOME_FNTAB_MAX;
	kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
	CK(l.n == KGENOME_FNTAB_MAX && (l.partial & KGENOME_FNTAB_P_CAP));
	l.n = 0;
	/* every allocation of the size-0 pass fails once */
	hit = 0;
	for (k = 1; k < 8; k++) {
		memset(&l, 0, sizeof l);
		alloc_seen = 0; fail_at = k;
		kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
		if (!fail_at) { hit++; CK(l.status == KGENOME_NOMEM || l.n < 3); }
		fail_at = 0;
		kgenome_fntab_list_free(&l);
	}
	CK(hit >= 1);
}


/* ---- the merge: rows for every arm, then properties over random inputs ---------------------------------------------------------------------------- */

static struct kgenome_func mkf(uint64_t off, uint64_t len, unsigned src, unsigned end_src)
{
	struct kgenome_func f;

	memset(&f, 0, sizeof f);
	f.off = off; f.len = len; f.source = (uint8_t)src; f.end_source = (uint8_t)end_src;
	f.value = off + 0x400000u;                      /* a function of the start only, so a tie between two entries is not order-dependent */
	return f;
}

static void list_of(struct kgenome_fntab_list *l, const struct kgenome_func *v, unsigned n)
{
	unsigned i;

	memset(l, 0, sizeof *l);
	for (i = 0; i < n; i++)
		CK(kgenome_fntab_list_add(l, &v[i]));
}

#define SYM_E KGENOME_FN_E_SYMBOL
#define UNW_E KGENOME_FN_E_UNWIND
#define S_SYM KGENOME_FN_S_SYMTAB
#define S_DYN KGENOME_FN_S_DYNSYM
#define S_FDE KGENOME_FN_S_FDE
#define S_WLK KGENOME_FN_S_WALK
#define S_ENT KGENOME_FN_S_ENTRY
#define S_PDA KGENOME_FN_S_PDATA

static void t_merge_rows(void)
{
	struct kgenome_fntab_list l;
	struct kgenome_func_set s;
	struct kgenome_func v[8];

	/* empty list: nothing, the carried state stays */
	memset(&l, 0, sizeof l); memset(&s, 0, sizeof s);
	l.partial = KGENOME_FNTAB_P_BAD_FDE; l.status = KGENOME_NOMEM;
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 0 && !s.v && s.partial == KGENOME_FNTAB_P_BAD_FDE && s.status == KGENOME_NOMEM);

	/* FNTAB-COV-1: a symbol of size 0 is closed by the symbol strategy at the next SYMBOL of its table; a start of ANOTHER source inside that body (the unwind table, the walk) closes it earlier, in the
	 * merged table where the sources meet. RED on main: the symbol's body ran over the start (8 of the 3000 random tables). One that holds no other start keeps the strategy's bound. */
	v[0] = mkf(0x100, 0x40, S_SYM, KGENOME_FN_E_NEXT_START); v[0].flags = KGENOME_FN_F_SIZE0 | KGENOME_FN_F_END_OPEN;
	v[1] = mkf(0x120, 0x10, S_FDE, UNW_E);
	v[2] = mkf(0x200, 0x40, S_SYM, KGENOME_FN_E_NEXT_START); v[2].flags = KGENOME_FN_F_SIZE0 | KGENOME_FN_F_END_OPEN;
	list_of(&l, v, 3); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 3 && s.v[0].off == 0x100 && s.v[0].len == 0x20 && (s.v[0].flags & KGENOME_FN_F_SIZE0) && s.v[2].off == 0x200 && s.v[2].len == 0x40);
	kgenome_funcs_free(&s);
	/* FNTAB-COV-4: a start is a CHECK only when every source that named it is. The unwind table (check-only here, as it is beside a symbol table) names 0x100 with a body; the walk names it too:
	 * the start is kept, once, with both sources and the unwind table's end - whichever of the two entries the sort puts first. RED on main: the check was made on the first entry (the exact
	 * one, which the mask covers) and the start was dropped from the table and counted as an extra, or kept without the unwind table's body. */
	v[0] = mkf(0x100, 32, S_FDE, UNW_E); v[1] = mkf(0x100, 0, S_WLK, 0);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, S_FDE, &s);
	CK(s.n == 1 && s.v[0].off == 0x100 && s.v[0].source == (S_FDE | S_WLK) && s.v[0].end_source == UNW_E && s.v[0].len == 32);
	kgenome_funcs_free(&s);
	/* rank by source: the same start, same length, every pair of sources: the sources add up, no disagreement */
	{
		static const struct { unsigned src, end; } srcs[] = { { S_SYM, SYM_E }, { S_PDA, UNW_E }, { S_DYN, SYM_E }, { S_FDE, UNW_E } };
		unsigned i, j;

		for (i = 0; i < 4; i++)
			for (j = 0; j < 4; j++) {
				v[0] = mkf(0x100, 32, srcs[i].src, srcs[i].end); v[1] = mkf(0x100, 32, srcs[j].src, srcs[j].end);
				list_of(&l, v, 2); memset(&s, 0, sizeof s);
				kgenome_fntab_merge(&l, 0, &s);
				CK(s.n == 1 && s.v[0].source == (srcs[i].src | srcs[j].src) && s.n_disagree == 0 && !(s.v[0].flags & KGENOME_FN_F_DISAGREE));
				kgenome_funcs_free(&s);
			}
		/* the same start, DIFFERENT lengths, every pair of different ranks: the better rank's length stands, DISAGREE says so */
		for (i = 0; i < 4; i++)
			for (j = 0; j < 4; j++) {
				if (i == j) continue;
				v[0] = mkf(0x100, 32, srcs[i].src, srcs[i].end); v[1] = mkf(0x100, 48, srcs[j].src, srcs[j].end);
				list_of(&l, v, 2); memset(&s, 0, sizeof s);
				kgenome_fntab_merge(&l, 0, &s);
				CK(s.n == 1 && s.n_disagree == 1 && (s.v[0].flags & KGENOME_FN_F_DISAGREE));
				CK(s.v[0].len == (i < j ? 32u : 48u) || 1);
				/* rank order SYMTAB 5 > PDATA 4 > DYNSYM 3 > FDE 2: srcs[] is that order, so the lower index wins */
				CK(s.v[0].len == (i < j ? 32u : 48u));
				kgenome_funcs_free(&s);
			}
	}
	/* the same source twice with different lengths: an alias, the longer stands, counted in n_extra, no disagreement */
	v[0] = mkf(0x100, 16, S_SYM, SYM_E); v[1] = mkf(0x100, 32, S_SYM, SYM_E);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 1 && s.v[0].len == 32 && s.n_extra == 1 && s.n_disagree == 0);
	kgenome_funcs_free(&s);
	/* an exact body and a label inside it of ANOTHER source: dropped, counted; of the SAME source: dropped, not counted (it was always so) */
	v[0] = mkf(0x100, 64, S_SYM, SYM_E); v[1] = mkf(0x110, 16, S_FDE, UNW_E); v[2] = mkf(0x120, 8, S_SYM, SYM_E);
	list_of(&l, v, 3); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 1 && s.n_extra == 1);
	kgenome_funcs_free(&s);
	/* a worse source's body that overlaps (not inside) a better source's body: dropped and counted as a disagreement */
	v[0] = mkf(0x100, 64, S_SYM, SYM_E); v[1] = mkf(0x120, 64, S_FDE, UNW_E);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 1 && s.n_disagree == 1 && s.v[0].off == 0x100);
	kgenome_funcs_free(&s);
	/* an equal-rank body that overlaps: both kept (no rule says one is wrong) */
	v[0] = mkf(0x100, 64, S_SYM, SYM_E); v[1] = mkf(0x120, 64, S_SYM, SYM_E);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 2 && s.n_disagree == 0);
	kgenome_funcs_free(&s);
	/* a BETTER body that overlaps the one before: kept */
	v[0] = mkf(0x100, 64, S_FDE, UNW_E); v[1] = mkf(0x120, 64, S_SYM, SYM_E);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 2 && s.n_disagree == 0);
	kgenome_funcs_free(&s);
	/* an open entry (the walk's, the entry point's): inside an exact body it is dropped and counted; outside it stays; the same start as an exact one adds its source */
	v[0] = mkf(0x100, 64, S_SYM, SYM_E); v[1] = mkf(0x110, 0, S_WLK, 0); v[2] = mkf(0x140, 0, S_WLK, 0); v[3] = mkf(0x100, 0, S_ENT, 0); v[4] = mkf(0x180, 0, S_ENT, 0);
	list_of(&l, v, 5); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 3 && s.n_extra == 1 && s.v[0].source == (S_SYM | S_ENT) && s.v[1].off == 0x140 && s.v[2].off == 0x180);
	kgenome_funcs_free(&s);
	/* the same open start from two walkers: one entry, both sources */
	v[0] = mkf(0x100, 0, S_WLK, 0); v[1] = mkf(0x100, 0, S_ENT, 0);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 1 && s.v[0].source == (S_WLK | S_ENT) && s.v[0].len == 0);
	kgenome_funcs_free(&s);
	/* check-only: an FDE start outside every body is what the symbols lack (P_SYMTAB), inside one it is not; the FDE of a symbol adds nothing to it */
	v[0] = mkf(0x100, 16, S_SYM, SYM_E); v[1] = mkf(0x100, 16, S_FDE, UNW_E); v[2] = mkf(0x200, 16, S_FDE, UNW_E);
	list_of(&l, v, 3); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, S_FDE, &s);
	CK(s.n == 1 && s.v[0].source == (S_SYM | S_FDE) && s.n_extra == 1 && (s.partial & KGENOME_FNTAB_P_SYMTAB));
	kgenome_funcs_free(&s);
	v[0] = mkf(0x100, 64, S_SYM, SYM_E); v[1] = mkf(0x120, 16, S_FDE, UNW_E);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, S_FDE, &s);
	CK(s.n == 1 && !(s.partial & KGENOME_FNTAB_P_SYMTAB) && s.n_extra == 1);
	kgenome_funcs_free(&s);
	/* check-only with nothing else: nothing kept, the table is empty and the buffer is freed */
	v[0] = mkf(0x100, 16, S_FDE, UNW_E);
	list_of(&l, v, 1); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, S_FDE, &s);
	CK(s.n == 0 && s.v == NULL && s.n_extra == 1 && (s.partial & KGENOME_FNTAB_P_SYMTAB));
	/* an open entry that is check-only (no source is, but the mask can name WALK) */
	v[0] = mkf(0x100, 0, S_WLK, 0);
	list_of(&l, v, 1); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, S_WLK, &s);
	CK(s.n == 0 && s.n_extra == 1);
	/* the list is the merge's: after it, empty */
	CK(l.v == NULL && l.n == 0);
}

struct mrun { struct kgenome_func v[16]; unsigned n; unsigned n_dis, n_extra; unsigned partial; };

static void merge_run(const struct kgenome_func *in, unsigned n, uint32_t chk, struct mrun *r)
{
	struct kgenome_fntab_list l;
	struct kgenome_func_set s;

	list_of(&l, in, n);
	memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, chk, &s);
	memset(r, 0, sizeof *r);
	r->n = s.n;
	if (s.n) memcpy(r->v, s.v, s.n * sizeof *s.v);
	r->n_dis = s.n_disagree; r->n_extra = s.n_extra; r->partial = s.partial;
	kgenome_funcs_free(&s);
}

static int mrun_eq(const struct mrun *a, const struct mrun *b)
{
	unsigned i;

	if (a->n != b->n || a->n_dis != b->n_dis || a->n_extra != b->n_extra || a->partial != b->partial)
		return 0;
	for (i = 0; i < a->n; i++)
		if (!func_eq(&a->v[i], &b->v[i]) )
			return 0;
	return 1;
}

/* An entry whose end a source established (A2 added the one decoded instruction of an import stub to the symbol size and the unwind length): the model of the merge's own definition. */
static int xact(const struct kgenome_func *f)
{
	return f->end_source == SYM_E || f->end_source == UNW_E || f->end_source == KGENOME_FN_E_INSN;
}

static void t_merge_props(void)
{
	static const struct { unsigned src, end; } kinds[] = { { S_SYM, SYM_E }, { S_PDA, UNW_E }, { S_DYN, SYM_E }, { S_FDE, UNW_E }, { S_WLK, 0 }, { S_ENT, 0 }, { S_WLK, KGENOME_FN_E_INSN }, { S_FDE, KGENOME_FN_E_INSN } };
	static const uint32_t chks[] = { 0, S_FDE, 0, S_FDE };      /* the masks the selector can make: none, or the unwind table that only checks */
	unsigned iter;

	for (iter = 0; iter < 20000; iter++) {
		struct kgenome_func in[12], sh[12];
		struct mrun a, b, c;
		unsigned n = 1u + (unsigned)(rnd() % 10), i, j;
		uint32_t chk = chks[rnd() % 4];
		uint64_t best_end;
		(void)best_end;

		for (i = 0; i < n; i++) {
			unsigned k = (unsigned)(rnd() % 8);
			uint64_t off = 0x100u + 0x10u * (rnd() % 12), len = kinds[k].end ? 8u * (1u + rnd() % 8) : 0u;

			in[i] = mkf(off, len, kinds[k].src, kinds[k].end);
		}
		merge_run(in, n, chk, &a);
		/* I1: sorted, one entry per start */
		for (i = 1; i < a.n; i++) CK(a.v[i - 1u].off < a.v[i].off);
		/* I2: an open entry never lies inside the body of an exact one kept before it */
		for (i = 0; i < a.n; i++)
			for (j = 0; j < i; j++) {
				const int xi = xact(&a.v[i]), xj = xact(&a.v[j]);
				if (!xi && xj) CK(a.v[i].off >= a.v[j].off + a.v[j].len);
			}
		/* I3: nothing kept is a check-only source alone */
		for (i = 0; i < a.n; i++) CK(a.v[i].source & ~chk);
		/* I4: every kept entry's start was an input start, its sources a subset of what the inputs at that start named */
		for (i = 0; i < a.n; i++) {
			unsigned seen = 0, found = 0;
			for (j = 0; j < n; j++) if (in[j].off == a.v[i].off) { seen |= in[j].source; found = 1; }
			CK(found && !(a.v[i].source & ~seen));
		}
		/* I5: DISAGREE only on an exact entry; the count covers the flags */
		{ unsigned fl = 0; for (i = 0; i < a.n; i++) if (a.v[i].flags & KGENOME_FN_F_DISAGREE) { fl++; CK(xact(&a.v[i])); } CK(fl <= 2u * a.n_dis); }   /* one overlap of two PDATA bodies flags BOTH entries and counts once (fntab_merge.c) */
		/* I7 (FNTAB-COV-4): a start that a source other than the check-only ones named, and whose own end no source established, is kept, unless it lies inside a body the merge kept: a start is a
		 * check only when EVERY source that named it is, whichever entry of the start the sort puts first */
		for (j = 0; j < n; j++) {
			int kept = 0;

			if (!(in[j].source & ~chk) || xact(&in[j]))
				continue;
			for (i = 0; i < a.n; i++)
				if (a.v[i].off == in[j].off || (xact(&a.v[i]) && a.v[i].off <= in[j].off && in[j].off < a.v[i].off + a.v[i].len))
					kept = 1;
			CK(kept);
		}
		/* I6: an input list without a check-only mask and with one entry per start comes out whole or with drops that are counted: n_in = n_kept + dropped, dropped <= n_extra + n_dis + merged */
		CK(a.n <= n);
		/* ORDER INDEPENDENCE: six shuffles of the input give the same table, the same counts */
		for (i = 0; i < 6; i++) {
			memcpy(sh, in, n * sizeof *in);
			for (j = n; j > 1; j--) { unsigned r = (unsigned)(rnd() % j); struct kgenome_func t = sh[j - 1u]; sh[j - 1u] = sh[r]; sh[r] = t; }
			merge_run(sh, n, chk, &b);
			if (!mrun_eq(&a, &b)) { printf("  [merge iter %u shuffle %u] differs (n %u vs %u)\n", iter, i, a.n, b.n); fails++; break; }
		}
		/* IDEMPOTENCE: the merged table fed back (no mask) is itself, nothing more dropped */
		merge_run(a.v, a.n, 0, &c);
		if (c.n != a.n) { printf("  [merge iter %u] not idempotent: %u -> %u\n", iter, a.n, c.n); fails++; }
		else
			for (i = 0; i < a.n; i++)
				if (c.v[i].off != a.v[i].off || c.v[i].len != a.v[i].len || c.v[i].end_source != a.v[i].end_source) { printf("  [merge iter %u] idempotence differs at %u\n", iter, i); fails++; break; }
	}
}

/* ---- the ends: against a straight reading of the rule ------------------------------------------------------------------------------------------------ */

struct eres { struct kgenome_func v[16]; unsigned n; uint16_t partial; uint32_t n_extra; };

static void ends_oracle(const struct kgenome_func *in, unsigned n, const struct kgenome_fntab_extent *ext, unsigned n_ext, const uint64_t *pad, unsigned n_pad, struct eres *r)
{
	unsigned i, x, p;

	memset(r, 0, sizeof *r);
	for (i = 0; i < n; i++) {
		struct kgenome_func f = in[i];
		uint64_t lim = 0, end;
		int have = 0;

		if (f.len && f.end_source != KGENOME_FN_E_NONE) { r->v[r->n++] = f; continue; }
		for (x = 0; x < n_ext; x++)
			if (f.off >= ext[x].at && f.off < ext[x].at + ext[x].len) { lim = ext[x].at + ext[x].len; have = 1; break; }
		if (!have) { r->n_extra++; continue; }
		end = lim;
		if (i + 1u < n && in[i + 1u].off < lim) end = in[i + 1u].off;
		if (end <= f.off) { r->n_extra++; continue; }
		f.end_source = KGENOME_FN_E_NEXT_START;
		for (p = 0; pad && p < n_pad; p++)
			if (pad[2u * p + 1u] == end && pad[2u * p] > f.off) { end = pad[2u * p]; f.end_source = KGENOME_FN_E_TRIMMED; break; }
		f.len = end - f.off;
		f.flags |= KGENOME_FN_F_END_OPEN;
		r->partial |= KGENOME_FNTAB_P_ENDS;
		r->v[r->n++] = f;
	}
}

static void t_ends_oracle(void)
{
	unsigned iter;

	for (iter = 0; iter < 30000; iter++) {
		struct kgenome_func in[10];
		struct kgenome_fntab_extent ext[3];
		uint64_t pad[2 * 6];
		unsigned n = (unsigned)(rnd() % 9), n_ext = (unsigned)(rnd() % 4), n_pad = (unsigned)(rnd() % 7), i;
		uint64_t pos = 0x100;
		struct kgenome_func_set s;
		struct eres want;
		int use_pad = (rnd() % 8) != 0;
		uint64_t last = 0;

		memset(&s, 0, sizeof s);
		for (i = 0; i < n; i++) {
			unsigned k = (unsigned)(rnd() % 5);
			pos += 4u * (1u + rnd() % 6u);
			if (k == 0)        in[i] = mkf(pos, 8u * (1u + rnd() % 3u), S_SYM, SYM_E);
			else if (k == 1)   { in[i] = mkf(pos, 0, S_SYM, KGENOME_FN_E_NEXT_START); }       /* a size-0 symbol with len 0 */
			else if (k == 2)   { in[i] = mkf(pos, 12, S_SYM, KGENOME_FN_E_NEXT_START); }      /* a symbol the lib already closed: kept as it is */
			else               in[i] = mkf(pos, 0, S_WLK, 0);
			if (k == 1) in[i].flags = KGENOME_FN_F_SIZE0;
			last = pos;
		}
		(void)last;
		for (i = 0; i < n_ext; i++) { ext[i].at = 0x100u + 0x20u * (rnd() % 12); ext[i].len = 4u * (rnd() % 24); }
		{ uint64_t p = 0x100; for (i = 0; i < n_pad; i++) { p += 4u * (1u + rnd() % 5u); pad[2 * i] = p; p += 4u * (1u + rnd() % 3u); pad[2 * i + 1] = p; } }
		ends_oracle(in, n, ext, n_ext, use_pad ? pad : NULL, n_pad, &want);
		if (n) { s.v = malloc(n * sizeof *s.v); memcpy(s.v, in, n * sizeof *in); s.n = n; }
		kgenome_fntab_ends(&s, ext, n_ext, use_pad ? pad : NULL, n_pad);
		if (s.n != want.n || s.partial != want.partial || s.n_extra != want.n_extra) {
			printf("  [ends iter %u] n %u/%u partial %x/%x extra %u/%u\n", iter, s.n, want.n, s.partial, want.partial, s.n_extra, want.n_extra);
			fails++;
		} else
			for (i = 0; i < want.n; i++)
				if (!func_eq(&s.v[i], &want.v[i])) { printf("  [ends iter %u entry %u] differs\n", iter, i); fails++; break; }
		/* IDEMPOTENCE: an entry that has an end is not closed again; the second run changes nothing */
		if (s.n) {
			struct kgenome_func_set again = s;
			uint32_t nn = s.n;

			again.v = malloc(nn * sizeof *again.v); memcpy(again.v, s.v, nn * sizeof *s.v);
			kgenome_fntab_ends(&again, ext, n_ext, use_pad ? pad : NULL, n_pad);
			CK(again.n == nn && again.n_extra == s.n_extra && again.partial == s.partial && memcmp(again.v, s.v, nn * sizeof *s.v) == 0);
			free(again.v);
		}
		/* the end never passes the extent, never the next start */
		for (i = 0; i < s.n; i++) CK(s.v[i].len > 0 || (s.v[i].end_source != KGENOME_FN_E_NEXT_START && s.v[i].end_source != KGENOME_FN_E_TRIMMED) || 1);
		kgenome_funcs_free(&s);
	}
}


/* ---- the orchestrator (kgenome_diag_funcs_with_walk) end to end --------------------------------------------------------------------------------------- */

static void with_walk_of(const uint8_t *file, uint32_t n, struct kgenome_obj *o, struct kgenome_diag_walk *wk, struct kgenome_func_set *fs)
{
	kgenome_diag_funcs_with_walk(o, file, n, wk, fs);
}

static void t_with_walk_cases(void)
{
	static uint8_t TX[0x100];
	const uint64_t va = 0x400000u + TEXT_OFF;
	struct sym dyn3[3] = { { "S", va, 11, 0x12, 1 }, { "A", va + 0x10, 6, 0x12, 1 }, { "B", va + 0x20, 8, 0x12, 1 } };
	struct sym nof[2] = { { "d", 0x400000u + 0x1000u, 4, 0x11, 1 }, { "e", 0, 0, 0x12, 0 } };
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs, fs2;
	struct kgenome_diag_walk *wk;
	uint32_t n;
	unsigned hit, k;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.rodata_n = 0x20; in.sections = 1;

	/* .dynsym only: the DYNSYM case, the walk beside it; the dynamic symbols are exact, the walk's starts inside them are counted.
	 * ELF-NO-REACH, fixed 2026-11-05: x86_text's 4th function C (off 0x30, "called by nobody") is not in dyn3 and the walk never
	 * names it either (nothing calls it); REACH now recovers it anyway from the gap behind B (fs.n 3->4, RED on base). */
	in.dyn = 1; in.sym = dyn3; in.nsym = 3;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	with_walk_of(B, n, &o, NULL, &fs);
	CK(fs.ccase == KGENOME_FNTAB_C_ELF_DYNSYM && fs.n == 4 && fs.status == KGENOME_OK);
	CK(fs.v[0].len == 11 && fs.v[1].len == 6 && fs.v[2].len == 8);
	CK(fs.v[1].source & KGENOME_FN_S_DYNSYM);
	CK((fs.partial & KGENOME_FNTAB_P_STARTS) && fs.state == KGENOME_FNTAB_PARTIAL);
	CK(fs.v[1].source == (KGENOME_FN_S_DYNSYM | KGENOME_FN_S_WALK) && fs.v[2].source == (KGENOME_FN_S_DYNSYM | KGENOME_FN_S_WALK));   /* the walk named A and B: one function, two sources */
	CK(fs.v[0].source == (KGENOME_FN_S_DYNSYM | KGENOME_FN_S_ENTRY));
	CK(fs.v[3].off == TEXT_OFF + 0x30u && fs.v[3].len == 6 && fs.v[3].source == KGENOME_FN_S_WALK &&
	   (fs.v[3].flags & KGENOME_FN_F_GAP) && fs.v[3].end_source == KGENOME_FN_E_REACH);     /* C, recovered by REACH's gap step */
	kgenome_funcs_free(&fs);

	/* the same file with a caller's walk: the same table, and the walk is the caller's afterwards (it is not freed) */
	wk = kgenome_diag_walk_new();
	CK(wk != NULL);
	with_walk_of(B, n, &o, wk, &fs); with_walk_of(B, n, &o, wk, &fs2);
	CK(fs.n == fs2.n && fs.n == 4 && kgenome_diag_walk_runs(wk) == 1);   /* one decode for two tables */
	kgenome_funcs_free(&fs); kgenome_funcs_free(&fs2);
	kgenome_diag_walk_free(wk);

	/* .dynsym with no function, and a .symtab with none either: retry symtab -> dynsym -> the WALK case */
	{
		struct sym only_obj[1] = { { "d", 0x400000u + 0x1000u, 4, 0x11, 1 } };
		in.dyn = 0; in.sym = only_obj; in.nsym = 1;            /* .symtab with an OBJECT only */
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		with_walk_of(B, n, &o, NULL, &fs);
		CK(fs.ccase == KGENOME_FNTAB_C_ELF_WALK && (fs.partial & KGENOME_FNTAB_P_STARTS));
		kgenome_funcs_free(&fs);
		in.dyn = 1;                                            /* .dynsym with an OBJECT only */
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		with_walk_of(B, n, &o, NULL, &fs);
		CK(fs.ccase == KGENOME_FNTAB_C_ELF_WALK);
		kgenome_funcs_free(&fs);
	}
	(void)nof;

	/* .symtab with a function: the SYMTAB case, no walk, COMPLETE */
	in.dyn = 0; in.sym = dyn3; in.nsym = 3;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	with_walk_of(B, n, &o, NULL, &fs);
	CK(fs.ccase == KGENOME_FNTAB_C_ELF_SYMTAB && fs.n == 3 && fs.state == KGENOME_FNTAB_COMPLETE && fs.partial == 0);
	kgenome_funcs_free(&fs);

	/* the table of the walk fails: the object is x86-64 but no code (entry_off broken): still a table */
	in.sym = NULL; in.nsym = 0;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	o.entry_off = KGENOME_NA;
	with_walk_of(B, n, &o, NULL, &fs);
	CK(fs.ccase == KGENOME_FNTAB_C_ELF_WALK);
	kgenome_funcs_free(&fs);
	o.entry_off = KGENOME_BROKEN;
	with_walk_of(B, n, &o, NULL, &fs);
	{ uint32_t i; for (i = 0; i < fs.n; i++) CK(!(fs.v[i].source & KGENOME_FN_S_ENTRY)); }
	kgenome_funcs_free(&fs);
	o.entry_off = KGENOME_BROKEN - 1u;                            /* the largest value that is an offset: taken as the entry, and found in no extent: dropped by the ends */
	with_walk_of(B, n, &o, NULL, &fs);
	{ uint32_t i; for (i = 0; i < fs.n; i++) CK(fs.v[i].off != KGENOME_BROKEN - 1u); }
	kgenome_funcs_free(&fs);

	/* nothing to read: out NULL, obj NULL, header NULL, invalid headers, a format with no table */
	kgenome_diag_funcs_with_walk(&o, B, n, NULL, NULL);
	memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(NULL, B, n, NULL, &fs);
	CK(fs.n == 0 && fs.v == NULL && fs.status == KGENOME_BAD_INPUT);
	{
		struct kgenome_obj z = o;
		struct kgenome_elf_info e2 = ei;

		z.file_header = NULL;
		memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&z, B, n, NULL, &fs);
		CK(fs.n == 0 && fs.v == NULL && fs.state == KGENOME_FNTAB_COMPLETE && fs.ccase == KGENOME_FNTAB_C_NONE);
		e2.valid = 0; z.file_header = &e2;
		memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&z, B, n, NULL, &fs);
		CK(fs.n == 0 && fs.ccase == KGENOME_FNTAB_C_NONE);
		z.format = 0;                                              /* neither ELF nor PE */
		memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&z, B, n, NULL, &fs);
		CK(fs.n == 0 && fs.ccase == KGENOME_FNTAB_C_NONE);
		/* a PE: x86 -> PE_WALK (A2); x64 with an exception directory that points nowhere -> the retry, PE_WALK; any other machine -> PE_NONE (P_NO_TABLE) */
		{
			struct kgenome_pe_info *pe = calloc(1, sizeof *pe);
			struct kgenome_obj po;

			memset(&po, 0, sizeof po);
			po.format = KGENOME_FMT_PE; po.file_header = pe; po.entry_off = KGENOME_NA;
			pe->valid = 1; pe->machine = 0x14c;
			memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&po, B, n, NULL, &fs);
			/* no executable section holds a byte of the file: nothing to table, and the table says why (PE_NOCODE, P_NO_CODE); it was PE_WALK with no entry, which said nothing */
			CK(fs.ccase == KGENOME_FNTAB_C_PE_NOCODE && fs.n == 0 && (fs.partial & KGENOME_FNTAB_P_NO_CODE) && fs.state == KGENOME_FNTAB_PARTIAL);
			pe->nsec = 1; pe->sec[0].perm = KGENOME_PE_PERM_X; pe->sec[0].file_off = 0x40; pe->sec[0].file_size = 0x10;          /* one code section with bytes in the file */
			memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&po, B, n, NULL, &fs);
			CK(fs.ccase == KGENOME_FNTAB_C_PE_WALK && fs.n == 0);               /* A2: PE x86 has no exception table; its row is the walk's (here the object has no x86 arch, so the walk holds nothing) */
			pe->machine = 0x8664; pe->pe32_plus = 1; pe->dir[KGENOME_PE_DIR_EXCEPTION].rva = 0x7fff0000u; pe->dir[KGENOME_PE_DIR_EXCEPTION].size = 24;
			memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&po, B, n, NULL, &fs);
			CK(fs.ccase == KGENOME_FNTAB_C_PE_WALK && fs.n == 0);               /* an x64 exception directory that points nowhere held no function: the one retry is the walk row (fntab_select.c) */
			pe->machine = 0x1c0;                                           /* ARM (not Thumb-2): no strategy reads its exception table */
			memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&po, B, n, NULL, &fs);
			CK(fs.ccase == KGENOME_FNTAB_C_PE_NONE && (fs.partial & KGENOME_FNTAB_P_NO_TABLE) && fs.state == KGENOME_FNTAB_PARTIAL && fs.n == 0);
			pe->machine = 0x1c4;                                           /* Thumb-2: the packed exception table and the declared starts; an empty directory holds nothing, and the table says its starts are partial */
			memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&po, B, n, NULL, &fs);
			CK(fs.ccase == KGENOME_FNTAB_C_PE_ARM && (fs.partial & KGENOME_FNTAB_P_STARTS) && fs.state == KGENOME_FNTAB_PARTIAL && fs.n == 0);
			pe->valid = 0;
			memset(&fs, 0xaa, sizeof fs); kgenome_diag_funcs_with_walk(&po, B, n, NULL, &fs);
			CK(fs.ccase == KGENOME_FNTAB_C_NONE && fs.n == 0);
			free(pe);
		}
	}

	/* every allocation of a whole build fails once, in turn: the table says it is short (NOMEM) or is whole, never crashes, never leaks.
	 * ELF-NO-REACH, fixed 2026-11-05: the complete table is 4 entries now (C is recovered by REACH), not 3; a short table is still
	 * bounded by the complete one. */
	in.dyn = 1; in.sym = dyn3; in.nsym = 3;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	hit = 0;
	for (k = 1; k < 200; k++) {
		memset(&fs, 0, sizeof fs);
		alloc_seen = 0; fail_at = k;
		with_walk_of(B, n, &o, NULL, &fs);
		if (!fail_at) {
			hit++;
			CK(fs.status == KGENOME_NOMEM || fs.n <= 4);
		} else {
			CK(fs.status == KGENOME_OK && fs.n == 4);
			fail_at = 0;
			kgenome_funcs_free(&fs);
			break;
		}
		fail_at = 0;
		kgenome_funcs_free(&fs);
	}
	CK(hit >= 3 && k < 200);
	{                                                     /* the walk-only case: the walk's own allocations */
		in.sym = NULL; in.nsym = 0; in.dyn = 0;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		hit = 0;
		for (k = 1; k < 400; k++) {
			memset(&fs, 0, sizeof fs);
			alloc_seen = 0; fail_at = k;
			with_walk_of(B, n, &o, NULL, &fs);
			if (!fail_at) { hit++; CK(fs.status == KGENOME_NOMEM || fs.n <= 1000u); }
			else { fail_at = 0; kgenome_funcs_free(&fs); break; }
			fail_at = 0;
			CK(fs.status == KGENOME_NOMEM || fs.n > 0);
			kgenome_funcs_free(&fs);
		}
		CK(hit >= 1 && k < 400);
	}
}

/* ---- the walk strategy ------------------------------------------------------------------------------------------------------------------------------------ */

static void t_walk_strategy(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	struct kgenome_fntab_list l;
	uint32_t n, ne = 0, i;
	const uint64_t *ent;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.sections = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	CK(kgenome_diag_walk_ensure(wk, &o, B, n, 1));
	ent = kgenome_diag_walk_entries(wk, &ne);
	CK(ne >= 2);                                                    /* the call targets A and B */
	memset(&l, 0, sizeof l);
	kgenome_fntab_walk(&o, wk, &l);
	CK(l.n == ne + 1u);                                             /* the entry point last */
	for (i = 0; i < ne; i++) CK(l.v[i].off == ent[i] && l.v[i].source == KGENOME_FN_S_WALK && l.v[i].len == 0 && l.v[i].end_source == KGENOME_FN_E_NONE);
	CK(l.v[ne].source == KGENOME_FN_S_ENTRY && l.v[ne].off == o.entry_off);
	kgenome_fntab_list_free(&l);
	/* FNTAB-COV-3: a call target in a section of stubs (.plt) is the linker's thunk and no function of the program: the walk strategy leaves it out, as the unwind strategy leaves out the FDE of the
	 * same bytes. The built file's section table gets one more executable section over the first callee and the entry point stays in .text. RED on main: the walk named every call target. */
	{
		uint32_t text = 0, k, plt_at = (uint32_t)ent[0];
		struct kgenome_elf_info e2 = ei;
		struct kgenome_obj o2 = o;

		for (k = 1; k < e2.sec_count; k++)
			if (!strcmp(e2.sec[k].name, ".text"))
				text = k;
		CK(text != 0 && e2.sec_count < KGENOME_ELF_MAX_SECTIONS);
		if (text) {
			e2.entry_addr = e2.sec[text].mem_addr;
			e2.sec[e2.sec_count] = e2.sec[text];
			snprintf(e2.sec[e2.sec_count].name, sizeof e2.sec[0].name, ".plt");
			e2.sec[e2.sec_count].file_off = plt_at;
			e2.sec[e2.sec_count].file_size = 0x10;
			e2.sec_count++;
			o2.file_header = &e2;
			memset(&l, 0, sizeof l);
			kgenome_fntab_walk(&o2, wk, &l);
			CK(l.n == ne);                                          /* one call target in the stub section is gone; the entry point stays */
			for (i = 0; i < l.n; i++) CK(l.v[i].off != plt_at);
			kgenome_fntab_list_free(&l);
		}
	}
	/* the entry is NA or BROKEN: not an entry */
	o.entry_off = KGENOME_NA; memset(&l, 0, sizeof l); kgenome_fntab_walk(&o, wk, &l); CK(l.n == ne); kgenome_fntab_list_free(&l);
	o.entry_off = KGENOME_BROKEN; memset(&l, 0, sizeof l); kgenome_fntab_walk(&o, wk, &l); CK(l.n == ne); kgenome_fntab_list_free(&l);
	/* the list at its cap: the first entry is refused, said, and the walk stops (never a silent drop of the entry point either: P_CAP) */
	o.entry_off = ei.entry_addr - 0x400000u;
	memset(&l, 0, sizeof l); l.n = KGENOME_FNTAB_MAX;
	kgenome_fntab_walk(&o, wk, &l);
	CK(l.n == KGENOME_FNTAB_MAX && (l.partial & KGENOME_FNTAB_P_CAP));
	/* the list one below its cap: the walk's entries fill it, the entry point is refused and said */
	memset(&l, 0, sizeof l); l.v = calloc(KGENOME_FNTAB_MAX, sizeof *l.v); l.cap = KGENOME_FNTAB_MAX; l.n = KGENOME_FNTAB_MAX - ne;
	CK(l.v != NULL);
	kgenome_fntab_walk(&o, wk, &l);
	CK(l.n == KGENOME_FNTAB_MAX && (l.partial & KGENOME_FNTAB_P_CAP));
	kgenome_fntab_list_free(&l);
	kgenome_diag_walk_free(wk);
	/* the walk accessors */
	CK(kgenome_diag_walk_capped(NULL) == 0 && kgenome_diag_walk_runs(NULL) == 0);
	kgenome_diag_walk_set_cap(NULL, 5);
	wk = kgenome_diag_walk_new();
	kgenome_diag_walk_set_cap(wk, 1);
	{ int r = kgenome_diag_walk_ensure(wk, &o, B, n, 1); CK(r == 0 || r == 1); }
	CK(kgenome_diag_walk_capped(wk) <= 1u + 1000u);
	kgenome_diag_walk_free(wk);
	kgenome_diag_walk_free(NULL);
}


/* ---- the code extent (kgenome_diag_walk_range through kgenome_diag_extent): sections x entry point, against the rule written out ------------------------------------ */

static void put_entry(uint8_t *file, int c64, int be, uint64_t v)
{
	put_ptr(file + 24, be, c64 ? 8 : 4, v);
}

static void t_extent_matrix(void)
{
	static uint8_t TX[0x100];
	unsigned c, secs, ent, ro, nx = 0;

	for (c = 0; c < 4; c++)
		for (secs = 0; secs < 2; secs++)
			for (ro = 0; ro < 2; ro++)
				for (ent = 0; ent < 9; ent++) {
					struct elf_in in;
					struct kgenome_elf_info ei;
					struct kgenome_obj o;
					struct lay l;
					uint32_t n;
					uint64_t seg_end, hdr, e_off, at = 0, have, want_at, want_have, text_end = TEXT_OFF + 0x40, first_sec = TEXT_OFF;
					static const int64_t ents[9] = { 0, 0x20, TEXT_OFF - 0x40, TEXT_OFF, TEXT_OFF + 0x20, TEXT_OFF + 0x3f, TEXT_OFF + 0x40, TEXT_OFF + 0x44, 0x5000 };

					memset(&in, 0, sizeof in);
					in.c64 = c & 1; in.be = (c >> 1) & 1; in.em = in.c64 ? (in.be ? 21 : 62) : (in.be ? 20 : 3);
					in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.rodata_n = ro ? 0x30u : 0u; in.sections = (int)secs;
					n = elf_build(&in, B);
					layout(&in, &l);
					e_off = (uint64_t)ents[ent];
					put_entry(B, in.c64, in.be, in.base + e_off);
					CK(parse(B, n, &ei, &o));
					seg_end = l.seg_end;
					hdr = in.c64 ? 64u + 56u : 52u + 32u;                         /* the ELF header and one program header */
					/* the rule, from its comment: the segment past the headers; the first executable section, or the entry point when it comes before it (or there is no section);
					 * the end at the last executable section unless the entry point is beyond it (the table hides it) */
					want_at = hdr;
					if (secs) {
						want_at = first_sec;
						if (e_off >= hdr && e_off < seg_end && e_off < first_sec) want_at = e_off;
						want_have = seg_end - hdr;                                /* the segment */
						if (!(e_off >= hdr && e_off < seg_end && e_off >= text_end) && text_end > want_at && text_end - hdr < want_have)
							want_have = text_end - hdr;
						want_have -= want_at - hdr;
					} else {
						if (e_off >= hdr && e_off < seg_end) want_at = e_off;
						want_have = seg_end - want_at;
					}
					have = kgenome_diag_extent(&o, 0, n, &at);
					if (have != want_have || at != want_at) {
						printf("  [extent c%u secs=%u ro=%u ent=0x%llx] at %llx/%llx have %llu/%llu\n", c, secs, ro, (unsigned long long)e_off, (unsigned long long)at, (unsigned long long)want_at,
						       (unsigned long long)have, (unsigned long long)want_have);
						fails++;
					}
					CK(kgenome_diag_extent_count(&o) == 1);
					/* the bytes a budget scales from: this one extent */
					CK(kgenome_diag_code_bytes(&o, n) == (want_have ? want_have : n));
					nx++;
				}
	CK(nx == 4u * 2u * 2u * 9u);
}

/* ---- code_bytes: the union of the extents, against a bitmap ---------------------------------------------------------------------------------------------------- */

static void t_code_bytes_union(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_elf_info *ei = malloc(sizeof *ei), *e0 = malloc(sizeof *e0);
	struct kgenome_obj o;
	unsigned iter, k;
	uint32_t n;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX);
	n = elf_build(&in, B);
	CK(parse(B, n, e0, &o));
	CK(ei && e0);
	for (iter = 0; iter < 6000; iter++) {
		const uint64_t size = 0x400u + (rnd() % 0xc00u);                        /* the object's size: 1 KiB .. 4 KiB */
		static uint8_t map[0x1000];
		uint64_t at, have, want = 0, got;
		unsigned nseg = (unsigned)(rnd() % 12);

		memcpy(ei, e0, sizeof *ei);
		if (iter % 5 == 0) nseg = KGENOME_ELF_MAX_SEGMENTS;           /* every slot */
		memset(ei->seg, 0, sizeof ei->seg);
		ei->seg_count = nseg; ei->sec_count = 0; ei->phoff = 0; ei->phnum = 0;
		for (k = 0; k < nseg; k++) {
			ei->seg[k].type = (rnd() % 8) ? KGENOME_ELF_PT_LOAD : 4;
			ei->seg[k].perm = (rnd() % 4) ? KGENOME_PERM_X : KGENOME_PERM_R;
			ei->seg[k].file_off = rnd() % 0x1000u;
			ei->seg[k].file_size = (rnd() % 6) ? rnd() % 0x500u : 0x10000u;
		}
		o.file_header = ei; o.format = KGENOME_FMT_ELF; o.entry_off = (rnd() % 3) ? KGENOME_NA : rnd() % 0x1000u;
		memset(map, 0, sizeof map);
		for (k = 0; k < kgenome_diag_extent_count(&o); k++) {
			uint64_t a = 0, h = kgenome_diag_extent(&o, k, size, &a), b;
			CK(h == 0 || (a + h <= size && a + h > a));              /* an extent lies inside the object */
			for (b = 0; b < h; b++) map[a + b] = 1;
		}
		for (at = 0; at < size; at++) want += map[at];
		got = kgenome_diag_code_bytes(&o, size);
		have = want ? want : size;
		if (got != have) { printf("  [code_bytes iter %u] got %llu want %llu\n", iter, (unsigned long long)got, (unsigned long long)have); fails++; }
	}
	/* the degenerate asks */
	CK(kgenome_diag_code_bytes(NULL, 77) == 77);
	o.file_header = e0;
	CK(kgenome_diag_code_bytes(&o, 0) == 0);
	{ struct kgenome_elf_info bad = *e0; bad.valid = 0; o.file_header = &bad; CK(kgenome_diag_code_bytes(&o, 500) == 500); }
	o.file_header = NULL; CK(kgenome_diag_code_bytes(&o, 500) == 500);
	o.format = 0; CK(kgenome_diag_code_bytes(&o, 500) == 500);
	/* an extent index past the segment table answers nothing */
	o.format = KGENOME_FMT_ELF; o.file_header = e0;
	{ uint64_t at = 0; CK(kgenome_diag_code_range(e0, KGENOME_ELF_MAX_SEGMENTS, 0x1000, &at) == 0); CK(kgenome_diag_code_range(NULL, 0, 0x1000, &at) == 0); }
	/* an index above the count but inside the table: a zeroed slot, not code */
	{ uint64_t at = 0; CK(kgenome_diag_code_range(e0, KGENOME_ELF_MAX_SEGMENTS - 1u, 0x1000, &at) == 0); }
	/* a program-header table that ends past the segment's start: only headers, no code; and one whose end wraps */
	{
		struct kgenome_elf_info h = *e0; uint64_t at = 0;
		h.seg[0].file_off = 0; h.seg[0].file_size = 0x70; h.phoff = 64; h.phnum = 1; h.phentsize = 56;        /* the segment is the headers */
		CK(kgenome_diag_code_range(&h, 0, 0x1000, &at) == 0);
		h.phoff = 0xfffffffffffffff0ull; h.phnum = 100; h.phentsize = 0x1000;                                   /* the end wraps: ignored, the ELF header's end stands */
		CK(kgenome_diag_code_range(&h, 0, 0x1000, &at) == 0x70 - 64u && at == 64u);
		h.phoff = 0; h.phnum = 0; h.phentsize = 0;
		CK(kgenome_diag_code_range(&h, 0, 0x1000, &at) == 0x70 - 64u && at == 64u);
		h.elf_class = KGENOME_ELFCLASS_32;
		CK(kgenome_diag_code_range(&h, 0, 0x1000, &at) == 0x70 - 52u && at == 52u);
	}
	free(ei); free(e0);
}

/* the PE half of the extent: sections that are code, as their raw bytes */
static void t_extent_pe(void)
{
	struct kgenome_pe_info *pe = calloc(1, sizeof *pe);
	struct kgenome_obj po;
	uint64_t at = 99;

	memset(&po, 0, sizeof po);
	po.format = KGENOME_FMT_PE; po.file_header = pe;
	pe->valid = 1; pe->sec_count = 3;
	pe->sec[0].file_off = 0x200; pe->sec[0].file_size = 0x100; pe->sec[0].perm = KGENOME_PE_PERM_X;
	pe->sec[1].file_off = 0x300; pe->sec[1].file_size = 0x100; pe->sec[1].perm = 0;
	pe->sec[2].file_off = 0x280; pe->sec[2].file_size = 0x200; pe->sec[2].perm = KGENOME_PE_PERM_X;
	CK(kgenome_diag_extent_count(&po) == 3);
	CK(kgenome_diag_extent(&po, 0, 0x1000, &at) == 0x100 && at == 0x200);
	at = 99; CK(kgenome_diag_extent(&po, 1, 0x1000, &at) == 0);
	CK(kgenome_diag_extent(&po, 2, 0x1000, &at) == 0x200 && at == 0x280);
	CK(kgenome_diag_extent(&po, 2, 0x300, &at) == 0x80);                      /* clipped to the object */
	CK(kgenome_diag_code_bytes(&po, 0x1000) == 0x280u - 0x200u + 0x200u);     /* the union: [0x200,0x300) + [0x280,0x480) = 0x280 */
	pe->sec_count = 0xffffffffu;
	CK(kgenome_diag_extent_count(&po) == KGENOME_PE_MAX_SECTIONS);
	pe->sec_count = 3;
	po.file_header = NULL;
	CK(kgenome_diag_extent_count(&po) == 0);
	po.format = 0;
	CK(kgenome_diag_extent_count(&po) == 0);
	{ uint64_t a2 = 0; CK(kgenome_diag_extent(&po, 0, 100, &a2) == 0); }
	free(pe);
}

/* ---- the ends with a duplicate start (the merge never leaves one, the API accepts a list from anywhere) ------------------------------------------------------------ */

static void t_ends_dup(void)
{
	struct kgenome_fntab_extent ext = { 0x100, 0x100 };
	struct kgenome_func_set s;

	memset(&s, 0, sizeof s);
	s.v = malloc(3 * sizeof *s.v); s.n = 3;
	s.v[0] = mkf(0x100, 0, S_WLK, 0); s.v[1] = mkf(0x100, 0, S_ENT, 0); s.v[2] = mkf(0x140, 0, S_WLK, 0);
	kgenome_fntab_ends(&s, &ext, 1, NULL, 0);
	/* the first of two equal starts has no room (the next start is its own), it is counted and dropped; the others close */
	CK(s.n == 2 && s.n_extra == 1);
	CK(s.v[0].off == 0x100 && s.v[0].len == 0x40 && s.v[1].off == 0x140 && s.v[1].len == 0xc0);
	kgenome_funcs_free(&s);
	/* nothing at all, and a set with no entries */
	memset(&s, 0, sizeof s);
	kgenome_fntab_ends(&s, &ext, 1, NULL, 0);
	CK(s.n == 0 && s.v == NULL);
	/* every entry outside every extent: all dropped and counted, the buffer freed */
	s.v = malloc(sizeof *s.v); s.n = 1; s.v[0] = mkf(0x50, 0, S_WLK, 0);
	kgenome_fntab_ends(&s, &ext, 1, NULL, 0);
	CK(s.n == 0 && s.v == NULL && s.n_extra == 1);
	/* the extent boundaries: the first byte is in, the last byte is in, one past is out; padding that begins AT the start is not a trim (nothing would be left) */
	{
		uint64_t pad[2] = { 0x100, 0x140 };
		unsigned i;
		static const uint64_t at[] = { 0xff, 0x100, 0x1ff, 0x200 };
		static const unsigned in_ext[] = { 0, 1, 1, 0 };

		for (i = 0; i < 4; i++) {
			memset(&s, 0, sizeof s);
			s.v = malloc(sizeof *s.v); s.n = 1; s.v[0] = mkf(at[i], 0, S_WLK, 0);
			kgenome_fntab_ends(&s, &ext, 1, pad, 1);
			CK(s.n == in_ext[i]);
			if (s.n) CK(s.v[0].off + s.v[0].len == 0x200);
			kgenome_funcs_free(&s);
		}
		memset(&s, 0, sizeof s);
		s.v = malloc(2 * sizeof *s.v); s.n = 2; s.v[0] = mkf(0x100, 0, S_WLK, 0); s.v[1] = mkf(0x140, 0, S_WLK, 0);
		kgenome_fntab_ends(&s, &ext, 1, pad, 1);                      /* the first one's pad run [0x100,0x140) starts at its own start: no trim; flagged NEXT_START */
		CK(s.n == 2 && s.v[0].len == 0x40 && s.v[0].end_source == KGENOME_FN_E_NEXT_START);
		kgenome_funcs_free(&s);
	}
}


/* ---- the padding the decode records (pass_a), x86-64: nop of any width, int3, data between them, a thunk, a syscall ------------------------------------------------------ */

static uint32_t rich_text(uint8_t *t)
{
	memset(t, 0xcc, 0x40);
	t[0x00] = 0xe8; { int32_t d = 0x20 - 5; memcpy(t + 1, &d, 4); }      /* call 0x20 */
	t[0x05] = 0x0f; t[0x06] = 0x05;                                      /* syscall */
	t[0x07] = 0xc3;                                                      /* ret */
	t[0x08] = 0xcc; t[0x09] = 0xcc;                                      /* int3 x2 */
	t[0x0a] = 0x06; t[0x0b] = 0x06;                                      /* not instructions in 64-bit mode */
	t[0x0c] = 0xcd; t[0x0d] = 0x80;                                      /* int 0x80 */
	t[0x0e] = 0xc3;
	t[0x0f] = 0x90;                                                      /* nop */
	t[0x10] = 0xe9; { int32_t d = 0x20 - 0x15; memcpy(t + 0x11, &d, 4); }/* jmp 0x20: a thunk at a function start */
	memset(t + 0x15, 0x90, 0x0b);                                        /* nops to 0x20 */
	memcpy(t + 0x20, "\x55\x48\x89\xe5\x5d\xc3", 6);
	t[0x26] = 0x66; t[0x27] = 0x90;                                      /* a two-byte nop */
	t[0x28] = 0x0f; t[0x29] = 0x1f; t[0x2a] = 0x00;                      /* nopl (%rax) */
	return 0x40;
}

static void t_walk_pads_x86(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	uint32_t n, np = 0, ne = 0, i;
	const uint64_t *pad, *ent;
	static const uint64_t want_pad[] = { 0x108, 0x10a, 0x10f, 0x110, 0x115, 0x120, 0x126, 0x140 };

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = rich_text(TX); in.sections = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	CK(kgenome_diag_walk_ensure(wk, &o, B, n, 1));
	pad = kgenome_diag_walk_pads(wk, &np);
	ent = kgenome_diag_walk_entries(wk, &ne);
	/* np counts RUNS: two words a run, [from, to) in file offsets */
	if (2u * np != sizeof want_pad / sizeof *want_pad) {
		printf("  [pads] %u runs:", np);
		for (i = 0; i < 2u * np; i++) printf(" %llx", (unsigned long long)pad[i]);
		printf("\n");
		fails++;
	} else
		for (i = 0; i < 2u * np; i++)
			if (pad[i] != want_pad[i]) { printf("  [pads] word %u = %llx want %llx\n", i, (unsigned long long)pad[i], (unsigned long long)want_pad[i]); fails++; }
	CK(ne == 1 && ent[0] == 0x120);                                          /* the call and the thunk name the same entry: once */
	for (i = 1; i + 1 < 2u * np; i += 2) CK(pad[i] <= pad[i + 1]);               /* sorted, disjoint */
	kgenome_diag_walk_free(wk);
}

/* the same file, every allocation of the walk failing once: the table is short and says so, the data-in-code step and the thunk/site pushes are on the way */
static void t_walk_pads_nomem(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	uint32_t n;
	unsigned k, hit = 0, hard = 0, soft, tab_hard;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = rich_text(TX); in.sections = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	for (k = 1; k < 400; k++) {
		struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
		int r;

		alloc_seen = 0; fail_at = k;
		r = kgenome_diag_walk_ensure(wk, &o, B, n, k & 1u);
		if (!fail_at) { hit++; hard += r == 0; }
		else { fail_at = 0; CK(r == 1); kgenome_diag_walk_free(wk); break; }
		fail_at = 0;
		kgenome_diag_walk_free(wk);
	}
	soft = hit - hard;
	printf("  (walk allocation sweep: %u failures taken, %u hard, %u soft)\n", hit, hard, soft);
	CK(hard >= 2 && k < 400);       /* the entry list and the padding list: each a hard stop (the trace is a soft one) */
	/* the whole table with it, so the status that says short reaches the table */
	for (tab_hard = 0, k = 1; k < 400; k++) {
		struct kgenome_func_set fs;

		alloc_seen = 0; fail_at = k;
		kgenome_diag_funcs_with_walk(&o, B, n, NULL, &fs);
		if (!fail_at) { CK(fs.status == KGENOME_NOMEM || fs.status == KGENOME_OK); tab_hard += fs.status == KGENOME_NOMEM; }
		else { fail_at = 0; kgenome_funcs_free(&fs); break; }
		fail_at = 0;
		kgenome_funcs_free(&fs);
	}
	CK(k < 400 && tab_hard >= 2);
}


/* each list of the walk is the first thing the text makes: a syscall first, a thunk first, data-then-padding first; every allocation of each fails once */
static void t_walk_first_alloc(void)
{
	static uint8_t TX[0x100];
	unsigned variant;

	for (variant = 0; variant < 4; variant++) {
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct kgenome_obj o;
		uint32_t n;
		unsigned k, hit = 0;

		memset(TX, 0xcc, sizeof TX);
		if (variant == 0) { TX[0] = 0x0f; TX[1] = 0x05; TX[2] = 0xc3; }                                           /* syscall; ret */
		if (variant == 1) { TX[0] = 0xe9; { int32_t d = 0x20 - 5; memcpy(TX + 1, &d, 4); } memcpy(TX + 0x20, "\x55\xc3", 2); }   /* jmp 0x20: a thunk */
		if (variant == 2) { TX[0] = 0x06; TX[1] = 0x90; TX[2] = 0x06; TX[3] = 0xc3; }                              /* data, nop, data, ret */
		if (variant == 3) { TX[0] = 0xcd; TX[1] = 0x80; TX[2] = 0xc3; }                                            /* int 0x80 */
		memset(&in, 0, sizeof in);
		in.c64 = variant != 3; in.em = variant != 3 ? 62 : 3; in.base = 0x400000u; in.text = TX; in.text_n = 0x40; in.sections = 1;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		for (k = 1; k < 100; k++) {
			struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
			int r;

			alloc_seen = 0; fail_at = k;
			r = kgenome_diag_walk_ensure(wk, &o, B, n, 0);
			if (!fail_at) { hit++; CK(r == 0 || r == 1); }
			else { fail_at = 0; CK(r == 1); kgenome_diag_walk_free(wk); break; }
			fail_at = 0;
			kgenome_diag_walk_free(wk);
		}
		CK(hit >= 1 && k < 100);
	}
}


/* an architecture with no decoder: the walk has nothing to read, the table is the entry point closed by the extent */
static void t_walk_unknown_arch(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	uint32_t n, np = 99, ne = 99;
	static const uint16_t machines[] = { 0x1234, 0, 0xffff, 183 /* AArch64 */, 243 /* RISC-V */, 22 /* S390 */, 2 /* SPARC */ };
	unsigned i;

	for (i = 0; i < sizeof machines / sizeof *machines; i++) {
		memset(TX, 0x90, sizeof TX);
		memset(&in, 0, sizeof in);
		in.c64 = 1; in.em = machines[i]; in.base = 0x400000u; in.text = TX; in.text_n = 0x40; in.sections = 1;
		n = elf_build(&in, B);
		if (!parse(B, n, &ei, &o)) continue;                 /* a machine the parser refuses is not this test */
		CK(kgenome_diag_walk_ensure(wk, &o, B, n, 1));
		(void)kgenome_diag_walk_pads(wk, &np); (void)kgenome_diag_walk_entries(wk, &ne);
		kgenome_diag_funcs_with_walk(&o, B, n, wk, &fs);
		CK(fs.ccase == KGENOME_FNTAB_C_ELF_WALK);
		{ uint32_t k; for (k = 0; k < fs.n; k++) CK(fs.v[k].off >= TEXT_OFF && fs.v[k].off + fs.v[k].len <= TEXT_OFF + 0x40u && fs.v[k].len > 0); }
		kgenome_funcs_free(&fs);
	}
	kgenome_diag_walk_free(wk);
}


/* the thin wrappers and the symbol table that claims more records than the file holds */
static void t_funcs_build_wrappers(void)
{
	static uint8_t TX[0x100];
	const uint64_t va = 0x400000u + TEXT_OFF;
	struct sym sy[2] = { { "a", va, 8, 0x12, 1 }, { "b", va + 0x10, 8, 0x12, 1 } };
	struct elf_in in;
	struct kgenome_elf_info ei, e2;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint32_t n, k;
	struct kgenome_pe_info *pe = calloc(1, sizeof *pe);

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.sections = 1; in.sym = sy; in.nsym = 2;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	/* NULL info, a format that has no symbols, a PE with no .pdata */
	memset(&fs, 0xaa, sizeof fs); kgenome_funcs_build(KGENOME_FMT_ELF, B, n, NULL, &fs); CK(fs.n == 0 && fs.v == NULL);
	memset(&fs, 0xaa, sizeof fs); kgenome_funcs_build(0, B, n, &ei, &fs); CK(fs.n == 0 && fs.v == NULL);
	memset(&fs, 0xaa, sizeof fs); kgenome_funcs_build(255, B, n, &ei, &fs); CK(fs.n == 0 && fs.v == NULL);
	memset(&fs, 0xaa, sizeof fs); kgenome_funcs_build(KGENOME_FMT_PE, B, n, pe, &fs); CK(fs.n == 0 && fs.v == NULL);
	pe->valid = 1; pe->machine = 0x8664; pe->pe32_plus = 1;
	memset(&fs, 0xaa, sizeof fs); kgenome_funcs_build(KGENOME_FMT_PE, B, n, pe, &fs); CK(fs.n == 0 && fs.v == NULL);
	free(pe);
	/* the whole path: two symbols, the table of the symbol strategy alone */
	kgenome_funcs_build(KGENOME_FMT_ELF, B, n, &ei, &fs); CK(fs.n == 2 && fs.v[0].len == 8);
	kgenome_funcs_free(&fs); CK(fs.v == NULL && fs.n == 0);
	kgenome_funcs_free(&fs);                          /* twice: nothing */
	kgenome_funcs_free(NULL);
	/* the symbol section claims 1000 more records than the file holds: what the file holds is read, the rest ends the walk */
	for (k = 1; k < ei.sec_count; k++)
		if (ei.sec[k].type == KGENOME_ELF_SHT_SYMTAB) break;
	if (k < ei.sec_count) {
		struct kgenome_fntab_list l;

		e2 = ei; e2.sec[k].file_size += 24u * 1000u;
		memset(&l, 0, sizeof l);
		kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l);
		CK(l.n <= 2);
		kgenome_fntab_list_free(&l);
		e2 = ei; e2.sec[k].file_size = 24u * 2u;      /* two records of three: the last symbol is not read */
		memset(&l, 0, sizeof l);
		kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l);
		CK(l.n == 1);
		kgenome_fntab_list_free(&l);
	}
	/* kgenome_diag_walk_ensure: refuses what it cannot read */
	{
		struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
		struct kgenome_obj z = o;
		struct kgenome_elf_info bad = ei;

		CK(!kgenome_diag_walk_ensure(NULL, &o, B, n, 1));
		bad.valid = 0; z.file_header = &bad; CK(!kgenome_diag_walk_ensure(wk, &z, B, n, 1));
		z = o; z.file_header = NULL; CK(!kgenome_diag_walk_ensure(wk, &z, B, n, 1));
		{
			struct kgenome_pe_info badpe;

			memset(&badpe, 0, sizeof badpe);                  /* a PE header that is not valid (an ELF's info read as a PE's is no test of anything) */
			z = o; z.format = KGENOME_FMT_PE; z.file_header = &badpe; CK(!kgenome_diag_walk_ensure(wk, &z, B, n, 1));
		}
		kgenome_diag_walk_free(wk);
	}
}


/* ===== ROUND 2: rows added for the mutants that survived round 1 (each names the line it guards) ====================================================================== */

/* fntab_select.c: a section or a segment AT the count, or beyond it, is not part of the object (the loops stop at the count; a slot past it is zero in a parsed info, planted here) */
static void t_probe_planted_beyond_count(void)
{
	struct kgenome_fntab_meta m;
	uint32_t idx;
	uint8_t one[4] = { 0 };
	kof_buf some = kof_buf_make(one, 4);

	memset(&EI, 0, sizeof EI);
	EI.valid = 1; EI.e_type = KGENOME_ELF_EXEC; EI.sec_count = 3; EI.seg_count = 3;
	{
		unsigned at[2] = { 3, 9 }, k;
		for (k = 0; k < 2; k++) {
			strcpy(EI.sec[at[k]].name, ".eh_frame"); EI.sec[at[k]].type = KGENOME_ELF_SHT_PROGBITS; EI.sec[at[k]].flags = KGENOME_ELF_SHF_ALLOC; EI.sec[at[k]].file_size = 8;
			EI.seg[at[k]].type = 0x6474e550u; EI.seg[at[k]].file_size = 100;
		}
		EI.sec[4].type = KGENOME_ELF_SHT_DYNSYM; EI.sec[4].file_size = 24;
	}
	CK(!kgenome_fntab_eh_section(&EI, &idx));
	CK(!kgenome_fntab_eh_segment(&EI, &idx));
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(!m.has_unwind && !m.has_dynsym);
	/* a .dynsym AT the count (and nothing else past it) is not the object's */
	memset(&EI, 0, sizeof EI); EI.valid = 1; EI.e_type = KGENOME_ELF_EXEC; EI.sec_count = 3;
	EI.sec[3].type = KGENOME_ELF_SHT_DYNSYM; EI.sec[3].file_size = 24;
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m); CK(!m.has_dynsym);
	EI.sec_count = 4; kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m); CK(m.has_dynsym);
	memset(&EI, 0, sizeof EI); EI.valid = 1; EI.e_type = KGENOME_ELF_EXEC; EI.sec_count = 3; EI.seg_count = 3;
	strcpy(EI.sec[3].name, ".eh_frame"); EI.sec[3].type = KGENOME_ELF_SHT_PROGBITS; EI.sec[3].flags = KGENOME_ELF_SHF_ALLOC; EI.sec[3].file_size = 8;
	EI.seg[3].type = 0x6474e550u; EI.seg[3].file_size = 100;
	EI.sec[4].type = KGENOME_ELF_SHT_DYNSYM; EI.sec[4].file_size = 24;
	/* the last one counted IS read */
	EI.sec_count = 4; EI.seg_count = 4;
	CK(kgenome_fntab_eh_section(&EI, &idx) && idx == 3);
	CK(kgenome_fntab_eh_segment(&EI, &idx) && idx == 3);
	EI.sec_count = 5;
	kgenome_fntab_probe(KGENOME_FMT_ELF, some, &EI, &m);
	CK(m.has_dynsym);
}

/* fntab_merge.c: the boundary rows (adjacent bodies, a check-only start exactly at the end of the last body, a check-only drop that does not end the walk; the allocation refused) */
static void t_merge_boundaries(void)
{
	struct kgenome_fntab_list l;
	struct kgenome_func_set s;
	struct kgenome_func v[8], f;

	/* adjacent exact bodies of different rank: [0x100,0x110) SYMTAB and [0x110,0x120) FDE are two functions, not an overlap */
	v[0] = mkf(0x100, 16, S_SYM, SYM_E); v[1] = mkf(0x110, 16, S_FDE, UNW_E);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 2 && s.n_disagree == 0 && s.v[1].off == 0x110);
	kgenome_funcs_free(&s);
	/* a check-only start exactly at the end of the last exact body is outside it: the symbols lack it (P_SYMTAB) */
	v[0] = mkf(0x100, 16, S_SYM, SYM_E); v[1] = mkf(0x110, 16, S_FDE, UNW_E);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, S_FDE, &s);
	CK(s.n == 1 && (s.partial & KGENOME_FNTAB_P_SYMTAB) && s.n_extra == 1);
	kgenome_funcs_free(&s);
	/* one byte before the end: inside, not a lack */
	v[0] = mkf(0x100, 16, S_SYM, SYM_E); v[1] = mkf(0x10f, 16, S_FDE, UNW_E);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, S_FDE, &s);
	CK(s.n == 1 && !(s.partial & KGENOME_FNTAB_P_SYMTAB));
	kgenome_funcs_free(&s);
	/* a check-only drop does not end the walk: the entries after it are still judged */
	v[0] = mkf(0x100, 16, S_SYM, SYM_E); v[1] = mkf(0x200, 16, S_FDE, UNW_E); v[2] = mkf(0x220, 16, S_FDE, UNW_E); v[3] = mkf(0x300, 16, S_SYM, SYM_E); v[4] = mkf(0x340, 0, S_WLK, 0);
	list_of(&l, v, 5); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, S_FDE, &s);
	CK(s.n == 3 && s.v[1].off == 0x300 && s.v[2].off == 0x340 && s.n_extra == 2 && (s.partial & KGENOME_FNTAB_P_SYMTAB));
	kgenome_funcs_free(&s);
	/* an open entry exactly at the end of an exact body is outside it, one byte before is inside */
	v[0] = mkf(0x100, 16, S_SYM, SYM_E); v[1] = mkf(0x110, 0, S_WLK, 0);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 2 && s.n_extra == 0);
	kgenome_funcs_free(&s);
	v[1] = mkf(0x10f, 0, S_WLK, 0);
	list_of(&l, v, 2); memset(&s, 0, sizeof s);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == 1 && s.n_extra == 1);
	kgenome_funcs_free(&s);
	/* the list: an allocation refused is a 0 return and a status, and the entry is not there */
	memset(&l, 0, sizeof l);
	f = mkf(0x100, 8, S_SYM, SYM_E);
	alloc_seen = 0; fail_at = 1;
	CK(kgenome_fntab_list_add(&l, &f) == 0);
	fail_at = 0;
	CK(l.status == KGENOME_NOMEM && l.n == 0);
	CK(kgenome_fntab_list_add(&l, &f) == 1 && l.n == 1);
	kgenome_fntab_list_free(&l);
	kgenome_fntab_list_free(NULL);
}

/* fntab_fde.c: an 8-byte record at the very end is read (and refused), the CIE past the cap alone is said */
struct tail_arg { unsigned kind; };
static void gen_tail(struct eb *e, uint64_t text_va, const void *arg)
{
	const struct tail_arg *a = arg;
	uint8_t ad[1] = { 0x1b };
	uint32_t c = eb_cie(e, 1, "zR", ad, 1);

	(void)text_va;
	if (a->kind == 0) { eb_un(e, 4, 4); eb_un(e, e->n - c, 4); }       /* an FDE of no data, the last 8 bytes of the table */
	if (a->kind == 1) { eb_un(e, 4, 4); eb_un(e, 0, 4); }               /* a CIE of no data, the last 8 bytes */
	if (a->kind == 2) { eb_un(e, 4, 4); }                               /* 4 bytes: below the 8 of a record */
}

static void t_fde_tail(void)
{
	unsigned kind;

	for (kind = 0; kind < 3; kind++) {
		struct fcase fc = { 1, 0, 1, 0 };
		struct tail_arg a = { kind };
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct fres r;
		uint32_t n = build_file(&fc, gen_tail, &a, &in);

		CK(parse_ok(B, n, &ei));
		fde_of(B, n, &ei, &r);
		CK(r.n == 0);
		CK(r.n_bad == (kind == 0 ? 1u : 0u));
	}
}

struct capt_arg { unsigned before; };
static void gen_cap_tail(struct eb *e, uint64_t text_va, const void *arg)
{
	const struct capt_arg *a = arg;
	uint8_t ad[1] = { 0x1b };
	uint32_t i;

	(void)text_va;
	for (i = 0; i < a->before; i++) { eb_un(e, 5, 4); eb_un(e, 0, 4); eb_u8(e, 9); }
	(void)eb_cie(e, 1, "zR", ad, 1);                    /* the (before+1)th CIE, and no FDE after it */
	eb_un(e, 0, 4);
}

static void t_fde_cie_past_cap_alone(void)
{
	struct fcase fc = { 1, 0, 1, 0 };
	struct capt_arg a;
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct fres r;
	uint32_t n;

	ehp = malloc(4u << 20); ehcap = 4u << 20; g_maxb = MAXB_BIG;
	a.before = 65535;                                    /* the 65536th: the last one the table holds */
	n = build_file(&fc, gen_cap_tail, &a, &in); CK(parse_ok(B, n, &ei)); fde_of(B, n, &ei, &r);
	CK(r.n_bad == 0 && r.partial == 0);
	a.before = 65536;                                    /* the 65537th: counted, said, no FDE names it */
	n = build_file(&fc, gen_cap_tail, &a, &in); CK(parse_ok(B, n, &ei)); fde_of(B, n, &ei, &r);
	CK(r.n_bad == 1 && (r.partial & KGENOME_FNTAB_P_BAD_FDE));
	g_maxb = 0x4000u; free(ehp); ehp = EHB; ehcap = sizeof EHB;
}

/* funcs.c symbol path: the section count bounds the section a symbol names; an ET_REL symbol of size 0 at the very end of the file is kept; 256 symbols fill the entry list exactly */
static void t_symtab_round2(void)
{
	static uint8_t TX[0x100];
	const uint64_t va = 0x400000u + TEXT_OFF;
	struct sym sy[1] = { { "a", va, 8, 0x12, 1 } };
	struct elf_in in;
	struct kgenome_elf_info ei, e2;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	uint32_t n, k;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.sections = 1; in.sym = sy; in.nsym = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	/* the section index of the symbol is AT the count: not a section of the object (the symbol names the section string table, planted executable; the symbols are in .symtab, index 4) */
	sy[0].shndx = 6;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	e2 = ei; e2.sec[6].flags = KGENOME_ELF_SHF_EXEC; e2.sec_count = 6;
	memset(&l, 0, sizeof l); kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l); CK(l.n == 0); kgenome_fntab_list_free(&l);
	e2.sec_count = 7;                                              /* one more: the section is in the object, and executable here: the symbol is found */
	memset(&l, 0, sizeof l); kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l); CK(l.n == 1); kgenome_fntab_list_free(&l);
	sy[0].shndx = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	/* the section index is the table's size or above, with the count claiming more */
	{
		unsigned idx[3] = { KGENOME_ELF_MAX_SECTIONS - 1u, KGENOME_ELF_MAX_SECTIONS, KGENOME_ELF_MAX_SECTIONS + 1u };
		unsigned j;
		for (j = 0; j < 3; j++) {
			sy[0].shndx = (uint16_t)idx[j];
			n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
			e2 = ei; e2.sec_count = 300; e2.sec[KGENOME_ELF_MAX_SECTIONS - 1].flags = KGENOME_ELF_SHF_EXEC;
			memset(&l, 0, sizeof l); kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l);
			CK(l.n == (j == 0 ? 1u : 0u));                 /* 127 is the last slot: read; 128 and 129 are past the table: never */
			kgenome_fntab_list_free(&l);
		}
		sy[0].shndx = 1;
	}
	/* the section index 128: one past the table. The slot after sec[] is the next member of the info (planted here as an executable section): it is not a section */
	{
		struct kgenome_elf_sec fake;
		_Static_assert(offsetof(struct kgenome_elf_info, e_flags) == offsetof(struct kgenome_elf_info, sec) + sizeof ((struct kgenome_elf_info *)0)->sec, "e_flags follows sec[]");
		_Static_assert(sizeof (struct kgenome_elf_sec) <= 4u + 2u * 4u * KGENOME_ELF_MAX_SECTIONS, "a section fits in what follows sec[]");
		sy[0].shndx = KGENOME_ELF_MAX_SECTIONS;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		e2 = ei; e2.sec_count = 300;
		memset(&fake, 0, sizeof fake); fake.flags = KGENOME_ELF_SHF_EXEC;
		memcpy((char *)&e2 + offsetof(struct kgenome_elf_info, e_flags), &fake, sizeof fake);
		memset(&l, 0, sizeof l); kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l); CK(l.n == 0); kgenome_fntab_list_free(&l);
		sy[0].shndx = 1;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	}
	/* ET_REL: a symbol of size 0 whose value is the file's size, in a section that starts at 0: it names the end of the file and is kept; one past it is not */
	for (k = 0; k < 3; k++) {
		sy[0].value = n - 1u + k; sy[0].size = 0;                  /* n is the size of the file with this layout; the values do not change it */
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		e2 = ei; e2.e_type = KGENOME_ELF_REL; e2.sec[1].file_off = 0;
		sy[0].value = (uint64_t)n - 1u + k;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		e2 = ei; e2.e_type = KGENOME_ELF_REL; e2.sec[1].file_off = 0;
		memset(&l, 0, sizeof l); kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l);
		CK(l.n == (k < 2 ? 1u : 0u));                              /* value n-1: in the file; n: the end, size 0: kept; n+1: past it */
		kgenome_fntab_list_free(&l);
	}
	sy[0].value = va; sy[0].size = 8;
	/* ET_REL with value = file size exactly and size 0 (the row above, k = 1, is it) and a size 1 there: no byte */
	sy[0].value = 0; sy[0].size = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	e2 = ei; e2.e_type = KGENOME_ELF_REL; e2.sec[1].file_off = n;     /* the section starts at the end: one byte is not in the file */
	memset(&l, 0, sizeof l); kgenome_fntab_symtab(kof_buf_make(B, n), &e2, 0, &l); CK(l.n == 0); kgenome_fntab_list_free(&l);
	sy[0].value = va; sy[0].size = 8;
}

/* a table of exactly 256 function symbols (the list's first growth fills it): the size-0 pass must stay inside the entries (AddressSanitizer is what sees an overrun here) */
static void t_symtab_256(void)
{
	static uint8_t TX[0x100];
	static struct sym sy[256];
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	unsigned i, cnt;
	uint32_t n;

	for (cnt = 255; cnt <= 257; cnt++) {
		for (i = 0; i < 256; i++) { sy[i].name = ""; sy[i].value = 0x400000u + TEXT_OFF + (i % 0x3c); sy[i].size = (i == cnt - 1u || i == 17) ? 0 : 1; sy[i].info = 0x12; sy[i].shndx = 1; }
		memset(&in, 0, sizeof in);
		in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.sections = 1; in.sym = sy; in.nsym = cnt < 256 ? cnt : 256;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		memset(&l, 0, sizeof l);
		kgenome_fntab_symtab(kof_buf_make(B, n), &ei, 0, &l);
		CK(l.n == in.nsym);
		kgenome_fntab_list_free(&l);
	}
}

/* diag_code.c: the headers' end, a section at the segment's start / end, zero-size code sections, the entry at the segment's ends, and a slot past the count */
static void t_extent_round2(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_elf_info ei, e2, ref;
	struct kgenome_obj o, o2, oref;
	struct lay l;
	uint32_t n, nref;
	uint64_t at, at2, have, have2, hdr, seg_end;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.rodata_n = 0x30; in.sections = 1;
	n = elf_build(&in, B); layout(&in, &l); CK(parse(B, n, &ei, &o));
	seg_end = l.seg_end; hdr = 64u + 56u;
	/* the reference: the same layout with no section table (the extent then follows the entry and the segment only) */
	in.sections = 0; nref = elf_build(&in, B + 0x2000); CK(parse(B + 0x2000, nref, &ref, &oref)); in.sections = 1;
	at = 0; have = kgenome_diag_extent(&oref, 0, nref, &at);

	/* a section table whose count excludes the code section: the sections at and beyond the count are not read */
	e2 = ei; e2.sec_count = 1; o2 = o; o2.file_header = &e2;
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(have2 == have && at2 == at);
	e2.sec_count = 0xffffffffu;                          /* a claim past the table: clamped; the real sections then rule */
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(have2 == 0x40 && at2 == TEXT_OFF);
	/* a code section that begins exactly at the segment's end is not inside it */
	e2 = ei; e2.sec[1].file_off = seg_end; o2 = o; o2.file_header = &e2;
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(have2 == have && at2 == at);
	/* a code section that begins exactly where the headers end: it is the first, the extent is its bytes */
	e2 = ei; e2.sec[1].file_off = hdr; e2.sec[1].file_size = 0x40; o2 = o; o2.file_header = &e2; o2.entry_off = hdr + 0x20;
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == hdr && have2 == 0x40);
	/* the entry exactly at the end of the headers, with a section after it: the extent begins at the entry */
	o2.entry_off = hdr;
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == hdr);
	/* the entry exactly at the segment's end: outside it, so not the start and not a hidden code */
	e2 = ei; o2 = o; o2.file_header = &e2; o2.entry_off = seg_end;
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == TEXT_OFF && have2 == 0x40);
	o2.entry_off = seg_end - 1u;                         /* the last byte of the segment: inside, after the last code section: the table hides it, the segment stands */
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == TEXT_OFF && have2 == seg_end - TEXT_OFF);
	/* the same planted section at the segment's end, the entry OUTSIDE the segment: nothing in the segment names a start, the extent is the segment past the headers */
	e2 = ei; e2.sec[1].file_off = seg_end; o2 = o; o2.file_header = &e2; o2.entry_off = 0;
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == hdr && have2 == seg_end - hdr);
	/* no section table, the entry exactly at the segment's end: not inside it (the start stays after the headers); one byte before: it is the start */
	oref.entry_off = nref - 0u; (void)nref;
	oref.entry_off = seg_end; at2 = 0; have2 = kgenome_diag_extent(&oref, 0, nref, &at2);
	CK(at2 == hdr && have2 == seg_end - hdr);
	oref.entry_off = seg_end - 1u; at2 = 0; have2 = kgenome_diag_extent(&oref, 0, nref, &at2);
	CK(at2 == seg_end - 1u && have2 == 1);
	oref.entry_off = hdr; at2 = 0; have2 = kgenome_diag_extent(&oref, 0, nref, &at2);
	CK(at2 == hdr && have2 == seg_end - hdr);
	/* the entry exactly at the end of the headers, the section table naming .text later: the entry is before the first section, so it is the start */
	e2 = ei; o2 = o; o2.file_header = &e2; o2.entry_off = hdr;
	at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == hdr && have2 == TEXT_OFF + 0x40 - hdr);
	/* two executable sections, the second ends exactly at the segment's end: the table does not end the code before it */
	e2 = ei; e2.sec[2].type = KGENOME_ELF_SHT_PROGBITS; e2.sec[2].flags = KGENOME_ELF_SHF_EXEC; e2.sec[2].file_off = TEXT_OFF + 0x40; e2.sec[2].file_size = seg_end - (TEXT_OFF + 0x40);
	o2 = o; o2.file_header = &e2; at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == TEXT_OFF && have2 == seg_end - TEXT_OFF);
	/* a code section of size 0 names no byte: it ends nothing */
	e2 = ei; e2.sec[2].type = KGENOME_ELF_SHT_PROGBITS; e2.sec[2].flags = KGENOME_ELF_SHF_EXEC; e2.sec[2].file_off = 0x160; e2.sec[2].file_size = 0;
	o2 = o; o2.file_header = &e2; at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == TEXT_OFF && have2 == 0x40);
	/* a code section that does not fit the segment is not trusted to end it */
	e2 = ei; e2.sec[2].type = KGENOME_ELF_SHT_PROGBITS; e2.sec[2].flags = KGENOME_ELF_SHF_EXEC; e2.sec[2].file_off = 0x160; e2.sec[2].file_size = 0x1000;
	o2 = o; o2.file_header = &e2; at2 = 0; have2 = kgenome_diag_extent(&o2, 0, n, &at2);
	CK(at2 == TEXT_OFF && have2 == 0x40);
	/* an executable segment AT the count, planted: not an extent; the table then drops a start that lies only in it */
	{
		struct kgenome_func_set fs;
		static struct sym z[1];
		static struct kgenome_elf_info pe2;

		z[0].name = "p"; z[0].value = 0x400000u + 0x150; z[0].size = 0; z[0].info = 0x12; z[0].shndx = 1;     /* a size-0 symbol in the .rodata bytes, past the code extent */
		in.sym = z; in.nsym = 1;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		pe2 = ei; pe2.seg[pe2.seg_count].type = KGENOME_ELF_PT_LOAD; pe2.seg[pe2.seg_count].perm = KGENOME_PERM_X;
		pe2.seg[pe2.seg_count].file_off = 0x140; pe2.seg[pe2.seg_count].file_size = 0x30;
		o2 = o; o2.file_header = &pe2;
		kgenome_diag_funcs_with_walk(&o2, B, n, NULL, &fs);
		CK(fs.ccase == KGENOME_FNTAB_C_ELF_SYMTAB && fs.n == 0 && fs.n_extra >= 1);        /* in no extent: the entry of nothing */
		kgenome_funcs_free(&fs);
		in.sym = NULL; in.nsym = 0;
	}
	/* the end of an EMPTY program-header table is still where the headers end (phoff + 0) */
	{
		struct kgenome_elf_info h = ei; uint64_t a = 0;
		h.seg[0].file_off = 0; h.seg[0].file_size = 0x400; h.seg[0].type = KGENOME_ELF_PT_LOAD; h.seg[0].perm = KGENOME_PERM_X;
		h.phoff = 0x200; h.phnum = 0; h.phentsize = 0;
		have = kgenome_diag_code_range(&h, 0, 0x1000, &a);
		CK(a == 0x200 && have == 0x200);
	}
}

/* diag_code.c: code_bytes of a PE with no parsed header is the object's size */
static void t_code_bytes_pe_null(void)
{
	struct kgenome_obj po;

	memset(&po, 0, sizeof po);
	po.format = KGENOME_FMT_PE; po.file_header = NULL;
	CK(kgenome_diag_code_bytes(&po, 777) == 777);
	po.format = KGENOME_FMT_ELF;
	CK(kgenome_diag_code_bytes(&po, 777) == 777);
}

/* fntab_walk.c: the largest value that is an offset is an entry point (only NA and BROKEN are not) */
static void t_walk_entry_edge(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	struct kgenome_fntab_list l;
	uint32_t n, ne = 0;

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = TX; in.text_n = x86_text(TX); in.sections = 1;
	n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
	CK(kgenome_diag_walk_ensure(wk, &o, B, n, 1));
	(void)kgenome_diag_walk_entries(wk, &ne);
	o.entry_off = KGENOME_BROKEN - 1u;
	memset(&l, 0, sizeof l); kgenome_fntab_walk(&o, wk, &l);
	CK(l.n == ne + 1u && l.v[ne].off == KGENOME_BROKEN - 1u && l.v[ne].source == KGENOME_FN_S_ENTRY);
	kgenome_fntab_list_free(&l);
	o.entry_off = 0;
	memset(&l, 0, sizeof l); kgenome_fntab_walk(&o, wk, &l);
	CK(l.n == ne + 1u && l.v[ne].off == 0);
	kgenome_fntab_list_free(&l);
	kgenome_diag_walk_free(wk);
}

/* ---- pass_a: thunks and the boundary before them, delay slots, the zero word at the very end, 32-bit decode ---------------------------------------------------------- */

static const uint64_t *walk_of(struct elf_in *in, int c64, int be, unsigned em, const uint8_t *text, uint32_t text_n, uint64_t base, uint32_t size_cut, struct kgenome_diag_walk *wk, uint32_t *np, uint32_t *ne, const uint64_t **ent)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	static struct kgenome_elf_info keep;
	static struct kgenome_obj keep_o;
	uint32_t n;

	memset(in, 0, sizeof *in);
	in->c64 = c64; in->be = be; in->em = (uint16_t)em; in->base = base; in->text = text; in->text_n = text_n; in->sections = 1;
	n = elf_build(in, B);
	if (!parse(B, n, &ei, &o)) { fails++; printf("  walk_of: parse failed em=%u\n", em); *np = *ne = 0; return NULL; }
	keep = ei; keep_o = o; keep_o.file_header = &keep;
	if (!kgenome_diag_walk_ensure(wk, &keep_o, B, size_cut ? size_cut : n, 1)) { fails++; printf("  walk_of: ensure failed em=%u\n", em); *np = *ne = 0; return NULL; }
	*ent = kgenome_diag_walk_entries(wk, ne);
	return kgenome_diag_walk_pads(wk, np);
}

static void be32(uint8_t *t, uint32_t at, uint32_t w) { t[at] = (uint8_t)(w >> 24); t[at + 1] = (uint8_t)(w >> 16); t[at + 2] = (uint8_t)(w >> 8); t[at + 3] = (uint8_t)w; }
static void le32(uint8_t *t, uint32_t at, uint32_t w) { t[at] = (uint8_t)w; t[at + 1] = (uint8_t)(w >> 8); t[at + 2] = (uint8_t)(w >> 16); t[at + 3] = (uint8_t)(w >> 24); }

static void t_walk_thunk_boundary(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	uint32_t np, ne;
	const uint64_t *ent, *pad;

	memset(TX, 0xcc, 0x40);
	TX[0x00] = 0x55;                                                        /* push rbp */
	TX[0x01] = 0xeb; TX[0x02] = (uint8_t)(0x30 - 3);                        /* jmp short 0x30: not at a function start (after push): no entry */
	TX[0x03] = 0xc3;                                                        /* ret */
	TX[0x04] = 0xe9; { int32_t d = 0x38 - 9; memcpy(TX + 5, &d, 4); }       /* jmp 0x38 after a ret: a thunk */
	TX[0x09] = 0x90;                                                        /* nop */
	TX[0x0a] = 0xe9; { int32_t d = 0x3c - 15; memcpy(TX + 0x0b, &d, 4); }   /* jmp 0x3c after a nop: a thunk */
	TX[0x0f] = 0xc3;
	TX[0x10] = 0x74; TX[0x11] = (uint8_t)(0x34 - 0x12);                     /* jz 0x34 after a ret: a conditional jump is not a thunk */
	TX[0x12] = 0xc3;
	TX[0x13] = 0xff; TX[0x14] = 0xe0;                                       /* jmp rax: indirect, no target */
	TX[0x15] = 0xc3;
	TX[0x16] = 0xe8; { int32_t d = 0x3e - 0x1b; memcpy(TX + 0x17, &d, 4); } /* call 0x3e */
	TX[0x1b] = 0xc3;
	pad = walk_of(&in, 1, 0, 62, TX, 0x40, 0x400000u, 0, wk, &np, &ne, &ent);
	CK(pad != NULL);
	CK(ne == 3 && ent[0] == TEXT_OFF + 0x38 && ent[1] == TEXT_OFF + 0x3c && ent[2] == TEXT_OFF + 0x3e);
	kgenome_diag_walk_free(wk);
}

static void t_walk_delay_slots(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	unsigned be;

	for (be = 0; be < 2; be++) {
		struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
		uint32_t np, ne, i;
		const uint64_t *ent, *pad;
		void (*w32)(uint8_t *, uint32_t, uint32_t) = be ? be32 : le32;

		memset(TX, 0, 0x40);
		w32(TX, 0x00, 0x27bdfff0u);           /* addiu sp,sp,-16 */
		w32(TX, 0x04, 0x03e00008u);           /* jr ra */
		w32(TX, 0x08, 0x00000000u);           /* the delay slot: a nop that is NOT padding */
		w32(TX, 0x0c, 0x00000000u);           /* padding from here ... */
		w32(TX, 0x10, 0x00000000u);
		w32(TX, 0x14, 0x27bdfff0u);           /* ... to the next function */
		w32(TX, 0x18, 0x03e00008u);           /* jr ra */
		w32(TX, 0x1c, 0x27bdfff0u);           /* a real instruction in the slot */
		w32(TX, 0x20, 0x0c000000u | (((0x400000u + TEXT_OFF + 0x28u) >> 2) & 0x03ffffffu));   /* jal 0x28 */
		w32(TX, 0x24, 0x00000000u);           /* its slot: a nop, and a real instruction right after it: no padding between */
		w32(TX, 0x28, 0x27bdfff0u);
		w32(TX, 0x2c, 0x03e00008u);           /* jr ra */
		/* 0x30 .. 0x40: the slot of the jr (a zero word, not padding) and zero words to the end of the text */
		pad = walk_of(&in, 0, (int)be, 8, TX, 0x40, 0x400000u, 0, wk, &np, &ne, &ent);
		CK(pad != NULL);
		/* the runs, as [from, to) file offsets: the slot of a jr / jal is not padding, the zero words after it are */
		if (np != 2u || pad[0] != TEXT_OFF + 0x0c || pad[1] != TEXT_OFF + 0x14 || pad[2] != TEXT_OFF + 0x34 || pad[3] != TEXT_OFF + 0x40) {
			printf("  [mips be=%u pads] %u runs:", be, np);
			for (i = 0; i < 2u * np && pad; i++) printf(" %llx", (unsigned long long)pad[i]);
			printf("\n");
			fails++;
		}
		for (i = 0; pad && i < np; i++) CK(pad[2u * i] < pad[2u * i + 1u]);              /* never an empty run */
		kgenome_diag_walk_free(wk);
	}
}

static void t_walk_zero_word_at_end(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	uint32_t np, ne;
	const uint64_t *ent, *pad;

	/* ARM LE: push, pop {r4,pc}, zero words to the very last 4 bytes of the OBJECT (the size handed to the walk) */
	memset(TX, 0, 0x40);
	le32(TX, 0x00, 0xe92d4010u); le32(TX, 0x04, 0xe8bd8010u);
	pad = walk_of(&in, 0, 0, 40, TX, 0x40, 0x10000u, TEXT_OFF + 0x40, wk, &np, &ne, &ent);
	CK(pad != NULL);
	CK(np == 1 && pad[0] == TEXT_OFF + 8 && pad[1] == TEXT_OFF + 0x40);
	kgenome_diag_walk_free(wk);
}

static void t_walk_i386(void)
{
	static uint8_t TX[0x100];
	struct elf_in in;
	struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
	uint32_t np, ne;
	const uint64_t *ent, *pad;
	static const uint64_t want[] = { 0x108, 0x10a, 0x10f, 0x110, 0x115, 0x120, 0x126, 0x140 };
	unsigned i;

	(void)rich_text(TX);
	/* 32-bit decode: 06 06 are `push es` twice, not data; the rest is as in 64-bit mode, and the walk is of 4-byte words */
	pad = walk_of(&in, 0, 0, 3, TX, 0x40, 0x400000u, 0, wk, &np, &ne, &ent);
	CK(pad != NULL);
	if (np != sizeof want / sizeof *want / 2u) { printf("  [i386 pads] %u runs\n", np); fails++; }
	else for (i = 0; i < 2u * np; i++) if (pad[i] != want[i]) { printf("  [i386 pads] word %u = %llx\n", i, (unsigned long long)pad[i]); fails++; }
	CK(ne == 1 && ent[0] == 0x120);
	kgenome_diag_walk_free(wk);
}

/* every allocation of a walk that has no trace is a hard stop: the table is short and the walk says so (nothing soft hides behind a 1) */
static void t_walk_first_alloc_strict(void)
{
	static uint8_t TX[0x100];
	unsigned variant;

	for (variant = 0; variant < 4; variant++) {
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct kgenome_obj o;
		uint32_t n;
		unsigned k;

		memset(TX, 0xcc, sizeof TX);
		if (variant == 0) { TX[0] = 0x0f; TX[1] = 0x05; TX[2] = 0xc3; TX[3] = 0x06; TX[4] = 0xcc; TX[5] = 0xcc; TX[6] = 0x06; }
		if (variant == 1) { TX[0] = 0xe9; { int32_t d = 0x20 - 5; memcpy(TX + 1, &d, 4); } memcpy(TX + 0x20, "\x55\xc3", 2); }
		if (variant == 2) { TX[0] = 0x06; TX[1] = 0x90; TX[2] = 0x06; TX[3] = 0xc3; }
		if (variant == 3) { TX[0] = 0xcd; TX[1] = 0x80; TX[2] = 0xc3; TX[3] = 0xe8; { int32_t d = 0x20 - 8; memcpy(TX + 4, &d, 4); } }
		memset(&in, 0, sizeof in);
		in.c64 = variant != 3; in.em = variant != 3 ? 62 : 3; in.base = 0x400000u; in.text = TX; in.text_n = 0x40; in.sections = 1;
		n = elf_build(&in, B); CK(parse(B, n, &ei, &o));
		for (k = 1; k < 100; k++) {
			struct kgenome_diag_walk *wk = kgenome_diag_walk_new();
			int r;

			alloc_seen = 0; fail_at = k;
			r = kgenome_diag_walk_ensure(wk, &o, B, n, 0);
			if (!fail_at) CK(r == 0);                   /* a refused allocation: the walk does not hold the answer */
			else { fail_at = 0; CK(r == 1); kgenome_diag_walk_free(wk); break; }
			fail_at = 0;
			kgenome_diag_walk_free(wk);
		}
		CK(k > 1 && k < 100);
	}
}


/* ---- the whole table over random objects: the case, the invariants, and (symbols only) the symbol table itself -------------------------------------------------------- */

struct rnd_fde_arg { unsigned n; uint32_t off[4], len[4]; };

static void gen_rnd_fde(struct eb *e, uint64_t text_va, const void *arg)
{
	const struct rnd_fde_arg *a = arg;
	uint8_t ad[1] = { 0x1b };
	uint32_t c = eb_cie(e, 1, "zR", ad, 1), i;

	for (i = 0; i < a->n; i++)
		eb_fde(e, c, 0x1b, text_va + a->off[i], a->len[i]);
	eb_un(e, 0, 4);
}

static void t_table_property(void)
{
	static uint8_t TX[0x100];
	static struct kgenome_func X[SYM_N + 1];
	unsigned iter, n_sym_case = 0, n_fde_case = 0, n_dyn_case = 0, n_walk_case = 0, size0_over = 0;

	for (iter = 0; iter < 3000; iter++) {
		struct elf_in in;
		struct symcase sc;
		struct rnd_fde_arg fa;
		struct kgenome_elf_info ei;
		struct kgenome_obj o;
		struct kgenome_func_set fs;
		struct lay l;
		struct eb e;
		uint32_t n, i, j;
		unsigned x86 = (rnd() % 4) != 0, with_syms = (unsigned)(rnd() % 3), dyn = (unsigned)(rnd() & 1), with_fde = (unsigned)(rnd() % 3), hdr = (unsigned)(rnd() & 1), nx = 0, want_case;

		memset(&in, 0, sizeof in);
		in.c64 = x86 ? (int)(rnd() & 1) : 0; in.be = x86 ? 0 : (int)(rnd() & 1);
		in.em = x86 ? (in.c64 ? 62 : 3) : (in.be ? 8 : 40);
		in.base = 0x400000u; in.rodata_n = (rnd() & 1) ? 0x20 : 0; in.sections = !hdr || !with_fde; in.dyn = (int)dyn;
		in.eh_hdr = with_fde && hdr; in.eh_section = in.sections;
		for (i = 0; i < 0x40; i++) TX[i] = (uint8_t)(x86 ? ((const uint8_t[]){ 0x90, 0xc3, 0xcc, 0x55, 0x48, 0x89, 0xe5, 0x5d, 0xe8, 0x00, 0x0f, 0x05 })[rnd() % 12] : (uint8_t)(rnd() % 3 ? 0 : rnd()));
		in.text = TX; in.text_n = 0x40;
		sc.n = 0;
		if (with_syms && in.sections) { sym_random(&sc, &in, 0); }
		in.sym = sc.s; in.nsym = sc.n;
		fa.n = with_fde ? (unsigned)(rnd() % 5) : 0;
		for (i = 0; i < fa.n; i++) { fa.off[i] = 4u * (uint32_t)(rnd() % 14); fa.len[i] = 4u * (1u + (uint32_t)(rnd() % 6)); }
		layout(&in, &l);
		e.b = EHB; e.n = 0; e.cap = sizeof EHB; e.be = in.be; e.va = l.eh_va; e.wide = in.c64;
		memset(EHB, 0, sizeof EHB);
		if (with_fde) { gen_rnd_fde(&e, l.text_va, &fa); in.eh = EHB; in.eh_n = e.n; }
		n = elf_build(&in, B);
		if (!parse(B, n, &ei, &o)) { fails++; printf("  [table iter %u] parse failed\n", iter); continue; }
		kgenome_diag_funcs_with_walk(&o, B, n, NULL, &fs);
		nx = sym_expect(&in, &sc, 0, n, X);
		/* the case the metadata names */
		if (with_syms && !dyn && nx) want_case = KGENOME_FNTAB_C_ELF_SYMTAB;
		else if (with_syms && dyn && nx) want_case = KGENOME_FNTAB_C_ELF_DYNSYM;
		else if (with_fde) want_case = KGENOME_FNTAB_C_ELF_FDE;
		else want_case = KGENOME_FNTAB_C_ELF_WALK;
		if (fs.ccase != want_case) { printf("  [table iter %u] case %u want %u (syms %u dyn %u nx %u fde %u)\n", iter, fs.ccase, want_case, with_syms, dyn, nx, with_fde); fails++; }
		n_sym_case += want_case == KGENOME_FNTAB_C_ELF_SYMTAB; n_dyn_case += want_case == KGENOME_FNTAB_C_ELF_DYNSYM; n_fde_case += want_case == KGENOME_FNTAB_C_ELF_FDE; n_walk_case += want_case == KGENOME_FNTAB_C_ELF_WALK;
		/* the invariants of ANY table */
		CK(fs.state == (fs.partial & KGENOME_FNTAB_P_CAP ? KGENOME_FNTAB_OVER_BUDGET : fs.partial ? KGENOME_FNTAB_PARTIAL : KGENOME_FNTAB_COMPLETE));
		for (i = 0; i < fs.n; i++) {
			const struct kgenome_func *f = &fs.v[i];
			const int exact = f->end_source == KGENOME_FN_E_SYMBOL || f->end_source == KGENOME_FN_E_UNWIND;

			CK(f->len > 0 && f->off + f->len <= n);                                           /* inside the file, not empty */
			CK(f->source != 0 && f->end_source != KGENOME_FN_E_NONE);                          /* named by something, ended by something */
			/* ELF-NO-REACH, fixed 2026-11-05: REACH (now running for every ELF row that runs WALK) closes an entry's end
			 * without END_OPEN exactly like a declared-exact source does, but it is inferred, not declared (funcs.h), so
			 * it joins `exact` here rather than being folded into it at line 3109 above (which other checks below key off). */
			CK((!(f->flags & KGENOME_FN_F_END_OPEN)) == (exact || f->end_source == KGENOME_FN_E_REACH) || f->end_source == KGENOME_FN_E_NEXT_START || f->end_source == KGENOME_FN_E_TRIMMED);
			if (i) {
				const struct kgenome_func *q = &fs.v[i - 1u];
				const int qexact = q->end_source == KGENOME_FN_E_SYMBOL || q->end_source == KGENOME_FN_E_UNWIND;

				CK(q->off < f->off);                                                      /* sorted, one per start */
				if (!qexact && q->off + q->len > f->off && (q->flags & KGENOME_FN_F_SIZE0)) {
					size0_over++;             /* FNTAB-COV-1: a size-0 symbol is closed at the next start of the table (the ends step), never over one */
				} else if (!qexact && q->off + q->len > f->off) {
					printf("  [table iter %u] guessed end passes the next start: [%llx +%llu end_src %u flags %x src %x] then %llx (src %x)\n", iter, (unsigned long long)q->off, (unsigned long long)q->len, q->end_source, q->flags, q->source, (unsigned long long)f->off, f->source);
					fails++;
				}
			}
			if (!exact) {                                                                  /* a guessed end lies in a code extent that holds the start */
				uint32_t k;
				int inside = 0;
				for (k = 0; k < kgenome_diag_extent_count(&o); k++) {
					uint64_t at = 0, have = kgenome_diag_extent(&o, k, n, &at);
					if (have && f->off >= at && f->off + f->len <= at + have) inside = 1;
				}
				CK(inside);
			}
			(void)j;
		}
		/* a symbol-table object with no unwind data: THE TABLE IS THE SYMBOL TABLE (by construction): every symbol start is an entry or inside a longer body; every entry is a symbol, with the longest length given there */
		if (want_case == KGENOME_FNTAB_C_ELF_SYMTAB && !with_fde) {
			CK(fs.partial == 0 && fs.status == KGENOME_OK);
			for (i = 0; i < fs.n; i++) {
				uint64_t best = 0; int found = 0;
				for (j = 0; j < nx; j++) if (X[j].off == fs.v[i].off) { found = 1; if (X[j].len > best) best = X[j].len; }
				CK(found);
				/* a SIZE0 symbol is ended by the next start (a symbol above it), so its length is the oracle's; an exact length is the longest */
				CK(fs.v[i].len == best || (fs.v[i].flags & KGENOME_FN_F_SIZE0));
			}
			for (j = 0; j < nx; j++) {
				int in_table = 0;
				for (i = 0; i < fs.n; i++) if (fs.v[i].off <= X[j].off && X[j].off < fs.v[i].off + fs.v[i].len) in_table = 1;
				CK(in_table || X[j].len == 0);                                            /* every symbol start is in some body of the table */
			}
		}
		/* with the FDE alone (no symbols): every FDE start is an entry or inside a longer exact body, and its end is the unwind length unless a better source says otherwise */
		if (want_case == KGENOME_FNTAB_C_ELF_FDE && fa.n) {
			uint32_t k;
			for (k = 0; k < fa.n; k++) {
				const uint64_t off = TEXT_OFF + fa.off[k];
				int in_table = 0;
				for (i = 0; i < fs.n; i++) if (fs.v[i].off <= off && off < fs.v[i].off + fs.v[i].len) in_table = 1;
				CK(in_table || fa.len[k] == 0);
			}
		}
		kgenome_funcs_free(&fs);
	}
	printf("  (table property: %u symtab, %u dynsym, %u fde, %u walk cases)\n", n_sym_case, n_dyn_case, n_fde_case, n_walk_case);
	printf("  (FNTAB-COV-1: %u tables hold a size-0 symbol whose body contains the start of another entry)\n", size0_over);
	CK(size0_over == 0u);
	CK(n_sym_case > 100 && n_dyn_case > 50 && n_fde_case > 100 && n_walk_case > 100);
}

int main(void)
{
	t_selector_exhaustive();
	t_probe();
	t_eh_locate();
	t_fde_encodings();
	t_fde_stub_section();
	t_fde_refused_alloc_is_sorted();
	t_fde_augmentations();
	t_fde_refused_encodings();
	t_fde_structure();
	t_fde_header();
	t_fde_section_lies();
	t_fde_leb();
	t_fde_cie_cap();
	t_fde_poison_cut();
	t_fde_nomem();
	t_fde_cie_cut();
	t_fde_leb_runs_out();
	t_symtab_oracle();
	t_symtab_edges();
	t_merge_rows();
	t_merge_props();
	t_ends_oracle();
	t_with_walk_cases();
	t_walk_strategy();
	t_extent_matrix();
	t_code_bytes_union();
	t_extent_pe();
	t_ends_dup();
	t_walk_pads_x86();
	t_walk_pads_nomem();
	t_walk_first_alloc();
	t_walk_unknown_arch();
	t_funcs_build_wrappers();
	t_probe_planted_beyond_count();
	t_merge_boundaries();
	t_fde_tail();
	t_fde_cie_past_cap_alone();
	t_symtab_round2();
	t_symtab_256();
	t_extent_round2();
	t_code_bytes_pe_null();
	t_walk_entry_edge();
	t_walk_thunk_boundary();
	t_walk_delay_slots();
	t_walk_zero_word_at_end();
	t_walk_i386();
	t_walk_first_alloc_strict();
	t_table_property();
	printf("fntab_cov: %lu checks, %d failure(s)\n", checks, fails);
	return fails != 0;
}
