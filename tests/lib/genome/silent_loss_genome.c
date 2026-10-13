/*
 * genome / silent_loss_genome - the limits of libgenome against the one invariant
 * a limit owes: FULL RESULT OR A SIGNAL. A caller must be able to tell "nothing
 * there" from "we stopped looking" (kgenome_status.h, CLAUDE.md section 12).
 *
 * Built from hand-made images in memory, linked against libkgenome.a alone.
 *
 * TWO KINDS OF CHECK.
 *
 *   CK(...)        the limit REPORTS (a status, an anomaly bit, a counter, a return
 *                  value, a flag) - or the limit is not reached. A normal check that
 *                  documents the signal and keeps it from being removed.
 *   KM_CHECK(...)  the limit DROPS evidence and nothing the caller can read says so.
 *                  `correct` is written as the expectation (every item kept, OR a
 *                  signal raised), so the check prints KNOWN-MISS while the product
 *                  is wrong and FAILS with FIXED-UNEXPECTEDLY the day it is fixed;
 *                  the cap string is "<LIMIT_NAME> <file>:<line> lost: <what>".
 *
 * Every limit of libgenome, with its class, is listed in the rows file of the audit;
 * this file holds the tests of the ones reachable from an object, an import
 * directory, a run or a sweep.
 */

#include <kgenome.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../unit/known_miss.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static void p16(uint8_t *b, uint64_t at, uint16_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}
static void p32(uint8_t *b, uint64_t at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void p64(uint8_t *b, uint64_t at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}

/* ======================================================================== *
 *  ELF parser: segment and section tables, section names                   *
 * ======================================================================== */

static uint8_t elf_a[1u << 15];

/*
 * ELF64 LE with `nph` program headers and `nsh` section headers. Section 1 is
 * the string table; section 2 is named with `name` (NUL-terminated copy at
 * offset 1 of it). Every other section is an empty PROGBITS with no name.
 */
static uint64_t elf_tables(unsigned nph, unsigned nsh, const char *name)
{
	const uint64_t phoff = 64, stroff = 0x2000, shoff = 0x3000;
	unsigned i;
	uint64_t n = shoff + (uint64_t)nsh * 64u;

	memset(elf_a, 0, sizeof elf_a);
	memcpy(elf_a, "\177ELF\2\1\1", 7);
	p16(elf_a, 16, 3);
	p16(elf_a, 18, 62);
	p32(elf_a, 20, 1);
	p64(elf_a, 32, phoff);
	p64(elf_a, 40, shoff);
	p16(elf_a, 52, 64);
	p16(elf_a, 54, 56);
	p16(elf_a, 56, (uint16_t)nph);
	p16(elf_a, 58, 64);
	p16(elf_a, 60, (uint16_t)nsh);
	p16(elf_a, 62, 1);
	for (i = 0; i < nph; i++) {
		uint64_t at = phoff + (uint64_t)i * 56u;

		p32(elf_a, at, 4);                       /* PT_NOTE */
		p64(elf_a, at + 8, 0x1000);
		p64(elf_a, at + 32, 4);
	}
	memcpy(elf_a + stroff + 1, name, strlen(name) + 1u);
	for (i = 1; i < nsh; i++) {
		uint64_t at = shoff + (uint64_t)i * 64u;

		p32(elf_a, at + 4, i == 1 ? 3u : 1u);    /* STRTAB, PROGBITS */
		p64(elf_a, at + 24, i == 1 ? stroff : 0x1000u);
		p64(elf_a, at + 32, i == 1 ? 0x100u : 4u);
	}
	p32(elf_a, shoff + 2u * 64u, 1);             /* section 2's name is at 1 */
	return n;
}

static void elf_limits(void)
{
	static struct kgenome_elf_info info;
	struct kgenome_obj obj;
	uint64_t n;
	unsigned i;

	/* KGENOME_ELF_MAX_SEGMENTS (64): a table of 70 is clamped, and the clamp is
	 * an anomaly bit - never a table that is simply shorter. */
	n = elf_tables(70, 4, ".text");
	CK(kgenome_elf_image_parse(kof_buf_make(elf_a, n), &info, &obj));
	CK(info.phnum_claimed == 70u);
	CK(info.seg_count == 64u || (info.anomalies & KGENOME_ELF_ANOM_PHNUM_CLAMPED));
	CK(info.seg_count < 70u && (info.anomalies & KGENOME_ELF_ANOM_PHNUM_CLAMPED));
	/* exactly at the limit nothing is flagged */
	n = elf_tables(64, 4, ".text");
	CK(kgenome_elf_image_parse(kof_buf_make(elf_a, n), &info, &obj));
	CK(info.seg_count == 64u && !(info.anomalies & KGENOME_ELF_ANOM_PHNUM_CLAMPED));

	/* KGENOME_ELF_MAX_SECTIONS (128): same. */
	n = elf_tables(1, 130, ".text");
	CK(kgenome_elf_image_parse(kof_buf_make(elf_a, n), &info, &obj));
	CK(info.shnum_claimed == 130u);
	CK(info.sec_count < 130u && (info.anomalies & KGENOME_ELF_ANOM_SHNUM_CLAMPED));
	n = elf_tables(1, 128, ".text");
	CK(kgenome_elf_image_parse(kof_buf_make(elf_a, n), &info, &obj));
	CK(info.sec_count == 128u && !(info.anomalies & KGENOME_ELF_ANOM_SHNUM_CLAMPED));

	/* KGENOME_ELF_SECNAME_MAX (32) and _SCAN (256): a name longer than the stored
	 * copy is cut AND said (SECNAME_TRUNC); the hash covers the whole name. */
	{
		char longname[80];
		uint32_t h40, h41;

		memset(longname, 'a', sizeof longname);
		longname[40] = 0;
		n = elf_tables(1, 4, longname);
		CK(kgenome_elf_image_parse(kof_buf_make(elf_a, n), &info, &obj));
		CK(info.anomalies & KGENOME_ELF_ANOM_SECNAME_TRUNC);
		CK(strlen(info.sec[2].name) == KGENOME_ELF_SECNAME_MAX - 1u);
		h40 = info.sec[2].name_hash;
		longname[40] = 'a';
		longname[41] = 0;
		n = elf_tables(1, 4, longname);
		CK(kgenome_elf_image_parse(kof_buf_make(elf_a, n), &info, &obj));
		h41 = info.sec[2].name_hash;
		CK(h40 != h41);          /* the comparison survives the cut */
		/* and a name that never ends inside the scan bound is said too */
		for (i = 0; i < 300u; i++)
			elf_a[0x2000 + 1u + i] = 'b';
		CK(kgenome_elf_image_parse(kof_buf_make(elf_a, n), &info, &obj));
		CK(info.anomalies & KGENOME_ELF_ANOM_SECNAME_TRUNC);
	}
}

/* ======================================================================== *
 *  ELF relocatable object: relocation table and call-site names            *
 * ======================================================================== */

#define NREL 3000u
static uint8_t rel_a[1u << 17];

/*
 * ET_REL x86-64: .text of NREL `call rel32` holes, .rela.text with one R_X86_64_PLT32
 * each against symbol 1 (undefined, named by `symname`), .symtab, .strtab, .shstrtab.
 */
static uint64_t rel_object(const char *symname)
{
	static const char shs[] = "\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab";
	const uint64_t text = 0x200, rela = 0x4000, sym = 0x16000, str = 0x16100,
		       shstr = 0x16300, sh = 0x16400;
	unsigned i;

	memset(rel_a, 0, sizeof rel_a);
	memcpy(rel_a, "\177ELF\2\1\1", 7);
	p16(rel_a, 16, 1);                           /* ET_REL */
	p16(rel_a, 18, 62);
	p32(rel_a, 20, 1);
	p64(rel_a, 40, sh);
	p16(rel_a, 52, 64);
	p16(rel_a, 58, 64);
	p16(rel_a, 60, 6);
	p16(rel_a, 62, 5);
	for (i = 0; i < NREL; i++) {
		rel_a[text + 5u * i] = 0xe8;
		p64(rel_a, rela + 24u * i, 5u * i + 1u);        /* r_offset */
		p64(rel_a, rela + 24u * i + 8u, (1ull << 32) | 4u); /* sym 1, PLT32 */
	}
	/* .symtab: null, then the undefined function whose name starts at 1 */
	p32(rel_a, sym + 24, 1);
	rel_a[sym + 24 + 4] = 0x12;                  /* GLOBAL FUNC */
	memcpy(rel_a + str + 1, symname, strlen(symname) + 1u);
	memcpy(rel_a + shstr, shs, sizeof shs);
	/* section headers: name offsets into shstr */
	{
		static const struct { uint32_t name, type; uint64_t flags, off, size; } s[] = {
			{ 0,  0, 0, 0, 0 },
			{ 1,  1, 6, 0x200, 5u * NREL },
			{ 7,  4, 0, 0x4000, 24u * NREL },
			{ 18, 2, 0, 0x16000, 48 },
			{ 26, 3, 0, 0x16100, 0x200 },
			{ 34, 3, 0, 0x16300, sizeof shs }
		};

		for (i = 0; i < 6u; i++) {
			uint64_t at = sh + 64u * i;

			p32(rel_a, at, s[i].name);
			p32(rel_a, at + 4, s[i].type);
			p64(rel_a, at + 8, s[i].flags);
			p64(rel_a, at + 24, s[i].off);
			p64(rel_a, at + 32, s[i].size);
			p32(rel_a, at + 40, i == 2u ? 3u : 0u);
			p64(rel_a, at + 56, i == 2u || i == 3u ? 24u : 0u);
		}
	}
	return sh + 6u * 64u;
}

struct rc_seen { unsigned n; size_t first_len; };

static void rc_cb(void *user, uint64_t at, uint64_t target, const char *name)
{
	struct rc_seen *r = user;

	(void)at;
	(void)target;
	if (!r->n)
		r->first_len = strlen(name);
	r->n++;
}

static void elf_reloc_names(void)
{
	static struct kgenome_elf_info info;
	struct kgenome_obj obj;
	struct kgenome_elf_relocs t;
	struct rc_seen seen = { 0, 0 };
	char name[121];
	uint64_t n;

	memset(name, 'k', 100);
	name[100] = 0;
	n = rel_object(name);
	CK(kgenome_elf_image_parse(kof_buf_make(rel_a, n), &info, &obj));
	CK(info.sec_count == 6u);
	CK(kgenome_elf_reloc_table(kof_buf_make(rel_a, n), &info, KGENOME_ELF_RELOC_CODE, &t) == NREL);
	/* NOT CAPPED: every one of the 3000 relocations and call sites is kept */
	CK(t.n == NREL);
	CK(kgenome_elf_relcalls(kof_buf_make(rel_a, n), &info, &t, rc_cb, &seen) == NREL);
	CK(seen.n == NREL);
	/*
	 * KGENOME_SYMNAME_MAX elf_image.h:162 - a symbol name is handed to the visitor
	 * cut to 63 bytes and nothing says it was cut (the visitor gets a plain
	 * string). Every vocabulary word is shorter, so what is lost is the identity of
	 * a symbol longer than that, e.g. a C++-mangled import.
	 */
	KM_CHECK(seen.first_len == 100u,
		 "a 100-byte undefined symbol is reported whole, or the cut is flagged",
		 "KGENOME_SYMNAME_MAX elf_image.h:162 lost: the tail of a symbol name over 63 bytes");
	kgenome_elf_reloc_table_free(&t);
}

/* ======================================================================== *
 *  PE: import directory, export directory                                  *
 * ======================================================================== */

#define PE_RAW 0x18000u
#define PE_FILE (0x400u + PE_RAW)
static uint8_t pe_a[PE_FILE];
static struct kgenome_pe_info pe_info;

/* The file offset of an RVA of the one section (rva 0x1000 at file 0x400). */
#define RAW(rva) (0x400u + ((rva) - 0x1000u))

/* PE32+, one RWX section holding rva 0x1000..0x19000, `nsec` section headers copied
 * from `sec` (rva, vsize) when given. Directories are filled by the caller. */
static void pe_base(unsigned nsec, const uint32_t (*sec)[2])
{
	unsigned i;

	memset(pe_a, 0, sizeof pe_a);
	pe_a[0] = 'M';
	pe_a[1] = 'Z';
	p32(pe_a, 0x3c, 0x80);
	memcpy(pe_a + 0x80, "PE\0\0", 4);
	p16(pe_a, 0x84, 0x8664);
	p16(pe_a, 0x86, (uint16_t)nsec);
	p16(pe_a, 0x94, 0xf0);
	p16(pe_a, 0x96, 0x22);
	p16(pe_a, 0x98, 0x20b);
	p32(pe_a, 0x98 + 16, 0x1000);                /* entry */
	p64(pe_a, 0x98 + 24, 0x140000000ull);
	p32(pe_a, 0x98 + 32, 0x1000);
	p32(pe_a, 0x98 + 36, 0x200);
	p32(pe_a, 0x98 + 56, 0x19000);
	p32(pe_a, 0x98 + 60, 0x400);
	p32(pe_a, 0x98 + 108, 16);
	for (i = 0; i < nsec; i++) {
		uint64_t at = 0x188u + 40u * i;

		memcpy(pe_a + at, ".text", 5);
		p32(pe_a, at + 8, sec ? sec[i][1] : PE_RAW);
		p32(pe_a, at + 12, sec ? sec[i][0] : 0x1000u);
		p32(pe_a, at + 16, PE_RAW);
		p32(pe_a, at + 20, 0x400);
		p32(pe_a, at + 36, 0xe0000020u);
	}
}

static int pe_parse(void)
{
	struct kgenome_obj obj;

	return kgenome_pe_image_parse(kof_buf_make(pe_a, sizeof pe_a), &pe_info, &obj);
}

static unsigned ex_n;
static int ex_cb(void *user, uint64_t nameoff, uint32_t rva)
{
	(void)user;
	(void)nameoff;
	(void)rva;
	ex_n++;
	return 1;
}

struct im_seen { unsigned n; size_t first_len; size_t dll_len; };
static void im_cb(void *user, uint64_t slot, const char *dll, const char *name,
		  uint32_t ordinal, uint64_t nameoff)
{
	struct im_seen *s = user;

	(void)slot;
	(void)ordinal;
	(void)nameoff;
	if (!s->n) {
		s->first_len = name ? strlen(name) : 0;
		s->dll_len = strlen(dll);
	}
	s->n++;
}

static void pe_exports(void)
{
	enum kgenome_status st;
	unsigned i, names = 5000;

	pe_base(1, NULL);
	p32(pe_a, 0x98 + 112, 0x1000);               /* export directory */
	p32(pe_a, 0x98 + 116, 0x100);
	p32(pe_a, RAW(0x1000) + 24, names);
	p32(pe_a, RAW(0x1000) + 28, 0x1100);         /* functions */
	p32(pe_a, RAW(0x1000) + 32, 0x2000);         /* names */
	p32(pe_a, RAW(0x1000) + 36, 0x7000);         /* ordinals */
	p32(pe_a, RAW(0x1100), 0x1000);
	for (i = 0; i < names; i++) {
		p32(pe_a, RAW(0x2000) + 4u * i, 0xa000u + 8u * i);
		p16(pe_a, RAW(0x7000) + 2u * i, 0);
		pe_a[RAW(0xa000u + 8u * i)] = 'n';
		pe_a[RAW(0xa000u + 8u * i) + 1u] = (uint8_t)('a' + i % 26u);
	}
	CK(pe_parse());
	ex_n = 0;
	/* EXP_NAMES_MAX (4096) pe_image.c:1055: the walk is cut AND says so. */
	CK(kgenome_pe_exports(kof_buf_make(pe_a, sizeof pe_a), &pe_info, ex_cb, NULL, &st) == 4096u);
	CK(ex_n == 4096u && st == KGENOME_TRUNCATED);
	/* at the limit it is whole */
	p32(pe_a, RAW(0x1000) + 24, 4096);
	ex_n = 0;
	CK(kgenome_pe_exports(kof_buf_make(pe_a, sizeof pe_a), &pe_info, ex_cb, NULL, &st) == 4096u);
	CK(st == KGENOME_OK);
}

static void pe_imports(void)
{
	enum kgenome_status st;
	struct im_seen seen;
	unsigned i;
	static const char dll70[] =
		"averyveryverylongdllnamethatisseventycharacterslongforsurexxxxxx.dll";

	/* --- one library, one import whose name is 100 bytes, a DLL name of 70 --- */
	pe_base(1, NULL);
	p32(pe_a, 0x98 + 120, 0x1000);               /* import directory */
	p32(pe_a, 0x98 + 124, 40);
	p32(pe_a, RAW(0x1000) + 0, 0x1100);          /* OriginalFirstThunk */
	p32(pe_a, RAW(0x1000) + 12, 0x1200);         /* Name */
	p32(pe_a, RAW(0x1000) + 16, 0x1300);         /* FirstThunk */
	memcpy(pe_a + RAW(0x1200), dll70, sizeof dll70);
	p64(pe_a, RAW(0x1100), 0x1400);
	p64(pe_a, RAW(0x1300), 0x1400);
	memset(pe_a + RAW(0x1400) + 2, 'f', 100);
	CK(pe_parse());
	memset(&seen, 0, sizeof seen);
	CK(kgenome_pe_imports(kof_buf_make(pe_a, sizeof pe_a), &pe_info, im_cb, &seen, &st) == 1u);
	CK(seen.n == 1u && st == KGENOME_OK);
	/*
	 * kgenome_pe_imports pe_image.c:945/987 (dll[64], name[64]) - the import name and
	 * the library name are handed over cut to 63 bytes, status OK.
	 */
	KM_CHECK(seen.first_len == 100u && seen.dll_len == sizeof dll70 - 1u,
		 "an import name and a DLL name over 63 bytes are reported whole, or a status says they were cut",
		 "IMPORT_NAME[64] pe_image.c:987 (dll[64] :945) lost: the tail of an import or library name over 63 bytes");

	/* --- the total thunk budget: 256 descriptors over one 4096-thunk table ---- */
	pe_base(1, NULL);
	p32(pe_a, 0x98 + 120, 0x1000);
	p32(pe_a, 0x98 + 124, 256u * 20u);
	for (i = 0; i < 256u; i++) {
		p32(pe_a, RAW(0x1000) + 20u * i + 0, 0x3000);
		p32(pe_a, RAW(0x1000) + 20u * i + 12, 0x2800);
		p32(pe_a, RAW(0x1000) + 20u * i + 16, 0x3000);
	}
	memcpy(pe_a + RAW(0x2800), "k.dll", 6);
	memcpy(pe_a + RAW(0xc000) + 2, "fn", 3);
	for (i = 0; i < 4096u; i++)
		p64(pe_a, RAW(0x3000) + 8u * i, 0xc000);
	CK(pe_parse());
	memset(&seen, 0, sizeof seen);
	{
		uint32_t n = kgenome_pe_imports(kof_buf_make(pe_a, sizeof pe_a), &pe_info,
						im_cb, &seen, &st);

		/* PE_FILE/8 thunks are all this file can hold: past them the walk says so */
		CK(n < 256u * 4096u && st == KGENOME_TRUNCATED);
	}
	/* the kept table carries the same status */
	{
		struct kgenome_pe_imptab t;

		kgenome_pe_imptab_build(kof_buf_make(pe_a, sizeof pe_a), &pe_info, &t);
		CK(t.status == KGENOME_TRUNCATED && t.n > 0u);
		kgenome_pe_imptab_free(&t);
	}
}

/* NSEC: more section headers than the parser keeps */
static void pe_sections(void)
{
	static uint32_t sec[100][2];
	unsigned i;

	for (i = 0; i < 100u; i++) {
		sec[i][0] = 0x1000u + 0x100u * i;
		sec[i][1] = 0x100;
	}
	pe_base(100, (const uint32_t (*)[2])sec);
	/* the section table of 100 x 40 bytes would run into the data; keep it inside
	 * the headers by moving it - the parser reads it where the header says */
	CK(pe_parse());
	CK(pe_info.nsec_claimed == 100u);
	/* KGENOME_PE_MAX_SECTIONS (96) pe_image.c:684 */
	CK(pe_info.sec_count < 100u && (pe_info.anomalies & KGENOME_PE_ANOM_NSEC_CLAMPED));
}

/*
 * kgenome_pe_layout_of pe_rebuild.c:438 - the produced image's section table is read
 * in address order and "one that is not is where this stops". The sections after the
 * break are not declared, and nothing says so (the return is a count that looks whole).
 */
static void pe_layout_order(void)
{
	static const uint32_t sec[3][2] = { { 0x1000, 0x1000 }, { 0x3000, 0x1000 }, { 0x2000, 0x1000 } };
	struct kgenome_sec_decl out[8];
	uint64_t entry = 0, base = 0;
	uint32_t n;

	pe_base(3, sec);
	n = kgenome_pe_layout_of(kof_buf_make(pe_a, sizeof pe_a), out, 8, &entry, &base, NULL);
	CK(n >= 1u);
	KM_CHECK(n == 3u,
		 "a section whose RVA is below the previous section's end is still declared, or the cut is signalled",
		 "PE_LAYOUT_ORDER pe_rebuild.c:438 lost: every section after an out-of-address-order entry of a produced image's table");
}

/* ======================================================================== *
 *  Function table of a normalised view                                     *
 * ======================================================================== */

static void funcs_remap(void)
{
	static uint8_t par[40000], view[40000];
	struct kgenome_func f[2];
	struct kgenome_func_set pf, out;
	uint32_t i;

	for (i = 0; i < sizeof par; i++)
		par[i] = (uint8_t)(i * 2654435761u >> 13);
	f[0].off = 0;      f[0].len = 64;  f[0].value = 0; f[0].shndx = 0;
	f[1].off = 10000;  f[1].len = 64;  f[1].value = 0; f[1].shndx = 0;
	pf.v = f;
	pf.n = 2;
	pf.status = KGENOME_OK;

	/* a view that keeps the order and drops a little padding: both are found */
	memcpy(view, par, 64);
	memcpy(view + 3000, par + 10000, 64);
	kgenome_funcs_remap(par, sizeof par, &pf, view, sizeof view, &out);
	CK(out.n == 2u && out.status == KGENOME_OK);
	kgenome_funcs_free(&out);

	/* the second function sits further past the first than REMAP_SLACK (4096) +
	 * its length: it is not in the view's set, and the set says nothing about it */
	memset(view, 0x5a, sizeof view);
	memcpy(view, par, 64);
	memcpy(view + 9000, par + 10000, 64);
	kgenome_funcs_remap(par, sizeof par, &pf, view, sizeof view, &out);
	KM_CHECK(out.n == 2u || out.status != KGENOME_OK,
		 "every function of the parent that the view still holds is listed, or a status says the search was cut",
		 "REMAP_SLACK funcs.c:113 lost: a function more than 4096 bytes past the previous one in the view");
	kgenome_funcs_free(&out);
}

/* ======================================================================== *
 *  xref: the sweep's tables                                                 *
 * ======================================================================== */

#define CODE_VA 0x1000u
#define DATA_VA 0x40000u

static void xref_feed(struct kgenome_xref *u, const uint8_t *code, uint32_t n, uint64_t va)
{
	uint32_t at = 0;

	kgenome_xref_begin(u, KGENOME_ARCH_X86_64);
	while (at < n) {
		struct kgenome_cell_insn in;
		uint32_t len = kgenome_cell_decode(KGENOME_ARCH_X86_64, 0, code + at, n - at,
						   va + at, &in);

		if (!len) {
			kgenome_xref_feed(u, NULL);
			at++;
			continue;
		}
		kgenome_xref_feed(u, &in);
		at += len;
	}
}

/* `lea rax,[rip+disp]` to an absolute address from `at` */
static uint32_t emit_lea_rax(uint8_t *c, uint32_t n, uint64_t at, uint64_t target)
{
	int32_t d = (int32_t)(target - (at + 7u));

	c[n++] = 0x48; c[n++] = 0x8d; c[n++] = 0x05;
	memcpy(c + n, &d, 4);
	return n + 4u;
}

static void xref_tables(void)
{
	static uint8_t code[8192];
	struct kgenome_xref *u;
	uint32_t n = 0, i;

	/* --- USE_MAX (512): distinct addresses past it set full ------------------ */
	u = kgenome_xref_new();
	CK(u != NULL);
	if (!u)
		return;
	for (i = 0; i < 600u; i++)
		n = emit_lea_rax(code, n, CODE_VA + n, DATA_VA + 16u * i);
	code[n++] = 0xc3;
	xref_feed(u, code, n, CODE_VA);
	CK(kgenome_xref_full(u) == 1);
	kgenome_xref_free(u);
	/* and exactly at the limit it is not full */
	u = kgenome_xref_new();
	n = 0;
	for (i = 0; i < 512u; i++)
		n = emit_lea_rax(code, n, CODE_VA + n, DATA_VA + 16u * i);
	code[n++] = 0xc3;
	xref_feed(u, code, n, CODE_VA);
	CK(kgenome_xref_full(u) == 0);
	kgenome_xref_free(u);

	/* --- the startup list: past USE_RGN (64) the call says no -------------------- */
	u = kgenome_xref_new();
	for (i = 0; i < 64u; i++)
		CK(kgenome_xref_startup(u, 0x2000u + i));
	CK(kgenome_xref_startup(u, 0x3000u) == 0);
	kgenome_xref_free(u);
}

/*
 * USE_RGN (64) xref.c:52 - "past the cap everything falls into the last region, which
 * blurs the grouping rather than losing it". It can LOSE the one fact the sweep exists
 * to give: USER (some code that is not startup executes the variable). Sixty-three RETs
 * fill the regions; U (not startup) then executes DATA_VA and returns, and the startup
 * address the caller names is the trailing code T, which resolves to the SAME last
 * region as U - so U's reference is read as a startup reference. No status, and
 * kgenome_xref_full stays 0 (it only knows USE_MAX).
 */
static void xref_region_cap(unsigned rets, uint32_t *flags_out)
{
	static uint8_t code[8192];
	struct kgenome_xref *u = kgenome_xref_new();
	uint32_t n = 0, i, t_at;

	for (i = 0; i < rets; i++)
		code[n++] = 0xc3;
	n = emit_lea_rax(code, n, CODE_VA + n, DATA_VA);
	code[n++] = 0xff; code[n++] = 0xd0;          /* call rax */
	code[n++] = 0xc3;                            /* U returns */
	t_at = n;
	code[n++] = 0x90;                            /* T: startup, ends without a ret */
	code[n++] = 0xeb; code[n++] = 0xfe;
	CK(kgenome_xref_startup(u, CODE_VA + t_at));
	xref_feed(u, code, n, CODE_VA);
	*flags_out = kgenome_xref_in(u, DATA_VA, 8);
	CK(kgenome_xref_full(u) == 0);
	kgenome_xref_free(u);
}

static void xref_regions(void)
{
	uint32_t few = 0, many = 0;

	xref_region_cap(5, &few);
	xref_region_cap(80, &many);
	/* the control: with few regions U is plainly user code */
	CK(few & KGENOME_XREF_CALL);
	CK(few & KGENOME_XREF_USER);
	CK(many & KGENOME_XREF_CALL);
	KM_CHECK((many & KGENOME_XREF_USER) != 0,
		 "code outside the startup set that executes a variable is flagged USER, or the sweep says its regions overflowed",
		 "USE_RGN xref.c:52 lost: the USER fact for code past the 64th region (merged into the startup region), no kgenome_xref_full");
}

/* ======================================================================== *
 *  The emulator's per-run tables                                            *
 * ======================================================================== */

#define ECODE 0x400000ull
#define STAGE 0x500000ull
#define EDATA 0x600000ull
#define ESTACK 0x7ffff000ull

static struct kgenome_emu *emu_with(const uint8_t *code, uint32_t n)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = 2000000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	if (!kgenome_emu_map(e, ECODE, code, n, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X) ||
	    !kgenome_emu_map(e, ESTACK, NULL, 0x1000, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W)) {
		kgenome_emu_free(e);
		return NULL;
	}
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, ESTACK + 0x800);
	kgenome_emu_set_rip(e, ECODE);
	return e;
}

/* exit(0): xor edi,edi ; mov eax,60 ; syscall */
static uint32_t emit_exit(uint8_t *c, uint32_t n)
{
	static const uint8_t x[] = { 0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05 };

	memcpy(c + n, x, sizeof x);
	return n + (uint32_t)sizeof x;
}

/* A chain of `stages` one-page stages: stage k jumps to stage k+1, the last exits. */
static struct kgenome_emu *emu_chain(unsigned stages)
{
	static uint8_t pg[0x1000];
	struct kgenome_emu *e;
	uint8_t first[8];
	unsigned k;

	/* the entry: jmp STAGE */
	first[0] = 0xe9;
	p32(first, 1, (uint32_t)(STAGE - (ECODE + 5u)));
	e = emu_with(first, 5);
	if (!e)
		return NULL;
	for (k = 0; k < stages; k++) {
		uint32_t n = 0;

		memset(pg, 0, sizeof pg);
		if (k + 1u < stages) {
			pg[n++] = 0xe9;
			p32(pg, n, (uint32_t)(STAGE + 0x1000u * (k + 1u) - (STAGE + 0x1000u * k + 5u)));
		} else {
			n = emit_exit(pg, n);
		}
		if (!kgenome_emu_map(e, STAGE + 0x1000ull * k, pg, 0x1000, 0x1000,
				     KGENOME_EMU_R | KGENOME_EMU_X)) {
			kgenome_emu_free(e);
			return NULL;
		}
	}
	return e;
}

static void emu_ranges(void)
{
	struct kgenome_emu *e;
	uint64_t rip = 0;
	uint32_t hops = 0;
	unsigned k;

	/* --- KGENOME_EMU_EXEC_WATCH (16) hop stages: 20 stages entered one by one ---- */
	e = emu_chain(20);
	CK(e != NULL);
	if (e) {
		for (k = 0; k < 20u; k++)
			kgenome_emu_hop_add(e, STAGE + 0x1000ull * k, STAGE + 0x1000ull * k + 0x1000u, 0);
		CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_EXIT);
		kgenome_emu_last_hop(e, &rip, &hops);
		KM_CHECK(hops == 20u,
			 "every stage the run enters is a hop (snapshot), or the table's overflow is signalled",
			 "KGENOME_EMU_EXEC_WATCH emu_api.c:502 lost: hop ranges past the 16th (a PE with >16 sections, a run that makes >16 mappings)");
		kgenome_emu_free(e);
	}
	e = emu_chain(16);
	if (e) {
		for (k = 0; k < 16u; k++)
			kgenome_emu_hop_add(e, STAGE + 0x1000ull * k, STAGE + 0x1000ull * k + 0x1000u, 0);
		CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_EXIT);
		kgenome_emu_last_hop(e, &rip, &hops);
		CK(hops == 16u);
		kgenome_emu_free(e);
	}

	/* --- watch_exec: 16 ranges the run never enters, then the one it does -------- */
	e = emu_chain(2);
	if (e) {
		for (k = 0; k < 16u; k++)
			kgenome_emu_watch_exec(e, 0x900000ull + 0x1000ull * k, 0x900000ull + 0x1000ull * k + 0x1000u);
		kgenome_emu_watch_exec(e, STAGE + 0x1000u, STAGE + 0x2000u);
		KM_CHECK(kgenome_emu_run(e) == KGENOME_EMU_STOP_HANDOFF,
			 "a watched range past the 16th still stops the run at the handover, or the declaration is refused visibly",
			 "KGENOME_EMU_EXEC_WATCH emu_private.h:151 lost: exec-watch ranges past the 16th (hollow sections of a packed PE)");
		kgenome_emu_free(e);
	}

	/* the control: the same range as the only watch stops the run */
	e = emu_chain(2);
	if (e) {
		kgenome_emu_watch_exec(e, STAGE + 0x1000u, STAGE + 0x2000u);
		CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_HANDOFF);
		kgenome_emu_free(e);
	}

	/* --- watch_write: same table size, and the observer is write_seen ----------- */
	{
		static const uint8_t w[] = {
			0x48, 0xbb, 0, 0, 0x70, 0, 0, 0, 0, 0,   /* mov rbx, 0x700000 */
			0xc6, 0x03, 0x01                         /* mov byte [rbx], 1 */
		};
		uint8_t code[64];
		uint32_t n = sizeof w;

		memcpy(code, w, sizeof w);
		n = emit_exit(code, n);
		e = emu_with(code, n);
		if (e) {
			CK(kgenome_emu_map(e, 0x700000, NULL, 0x1000, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W));
			for (k = 0; k < 16u; k++)
				kgenome_emu_watch_write(e, 0x900000ull + 0x1000ull * k, 0x900000ull + 0x1000ull * k + 0x1000u);
			kgenome_emu_watch_write(e, 0x700000, 0x701000);
			(void)kgenome_emu_run(e);
			KM_CHECK(kgenome_emu_write_seen(e) != 0,
				 "a write into a watched range past the 16th is seen, or the declaration is refused visibly",
				 "KGENOME_EMU_EXEC_WATCH emu_private.h:151 lost: write-watch ranges past the 16th");
			kgenome_emu_free(e);
		}
		/* the control: the same range as the only watch is seen */
		e = emu_with(code, n);
		if (e) {
			CK(kgenome_emu_map(e, 0x700000, NULL, 0x1000, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W));
			kgenome_emu_watch_write(e, 0x700000, 0x701000);
			(void)kgenome_emu_run(e);
			CK(kgenome_emu_write_seen(e) != 0);
			kgenome_emu_free(e);
		}
	}
}

static void emu_insn_watch(void)
{
	uint8_t code[32];
	struct kgenome_emu *e;
	uint32_t n = 0;
	unsigned k;

	code[n++] = 0x90;                            /* the instruction patterns are asked about */
	n = emit_exit(code, n);
	e = emu_with(code, n);
	CK(e != NULL);
	if (!e)
		return;
	for (k = 0; k < 8u; k++) {
		uint8_t b = (uint8_t)(0xe0u + k);

		kgenome_emu_watch_insn(e, &b, 1);
	}
	{
		uint8_t nop = 0x90;

		kgenome_emu_watch_insn(e, &nop, 1);      /* the ninth pattern */
	}
	KM_CHECK(kgenome_emu_run(e) == KGENOME_EMU_STOP_INSN,
		 "the ninth instruction pattern pauses the run, or the declaration is refused visibly",
		 "KGENOME_EMU_INSN_WATCH emu_api.c:577 lost: instruction patterns past the 8th (void return)");
	kgenome_emu_free(e);
	/* the control: the same pattern as the only one pauses the run */
	e = emu_with(code, n);
	if (e) {
		uint8_t nop = 0x90;

		kgenome_emu_watch_insn(e, &nop, 1);
		CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_INSN);
		kgenome_emu_free(e);
	}
}

/* 70 distinct written pages, each made executable: one snapshot each is the contract */
static void emu_snapshots(void)
{
	/* mov rbx,EDATA ; mov r12,70 ; L: mov byte [rbx],1 ; mov rdi,rbx ; mov esi,0x1000 ;
	 * mov edx,5 ; mov eax,10 ; syscall ; add rbx,0x1000 ; dec r12 ; jnz L ; exit */
	static const uint8_t pro[] = {
		0x48, 0xbb, 0, 0, 0x60, 0, 0, 0, 0, 0,
		0x49, 0xc7, 0xc4, 70, 0, 0, 0
	};
	static const uint8_t body[] = {
		0xc6, 0x03, 0x01,
		0x48, 0x89, 0xdf,
		0xbe, 0x00, 0x10, 0, 0,
		0xba, 5, 0, 0, 0,
		0xb8, 10, 0, 0, 0,
		0x0f, 0x05,
		0x48, 0x81, 0xc3, 0x00, 0x10, 0, 0,
		0x49, 0xff, 0xcc
	};
	uint8_t code[128];
	struct kgenome_emu *e;
	uint32_t n = 0, it = 0, got = 0, back;
	uint64_t va, len;
	const uint8_t *bytes;

	memcpy(code, pro, sizeof pro);
	n = sizeof pro;
	memcpy(code + n, body, sizeof body);
	n += sizeof body;
	back = (uint32_t)(0 - (int32_t)(sizeof body + 2u));
	code[n++] = 0x75;
	code[n++] = (uint8_t)back;
	n = emit_exit(code, n);
	e = emu_with(code, n);
	CK(e != NULL);
	if (!e)
		return;
	CK(kgenome_emu_map(e, EDATA, NULL, 70u * 0x1000u, 70u * 0x1000u, KGENOME_EMU_R | KGENOME_EMU_W));
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_EXIT);
	while (kgenome_emu_next_snapshot(e, &it, &va, &bytes, &len))
		got++;
	CK(got == KGENOME_EMU_MAX_SNAP);
	KM_CHECK(got == 70u,
		 "every page the run wrote and then made executable has a snapshot, or the overflow is signalled",
		 "KGENOME_EMU_MAX_SNAP emu_api.c:630 lost: snapshots past the 64th (the unpacked payload of a stub that mprotects X many times)");
	kgenome_emu_free(e);
}

/* The emulator's shim table: the 17th declaration is refused by its return value. */
static void emu_shims(void)
{
	struct kgenome_emu *e = emu_with((const uint8_t *)"\xc3", 1);
	char nm[32];
	unsigned k, ok = 0;

	CK(e != NULL);
	if (!e)
		return;
	for (k = 0; k < 20u; k++) {
		unsigned api = k % kgenome_emu_win_api_count();

		/* distinct names: the first 17 distinct APIs */
		snprintf(nm, sizeof nm, "%s", kgenome_emu_win_api_name(api + (k >= 16u ? 20u : 0u)));
		ok += (unsigned)(kgenome_emu_shim_api(e, nm, 1) != 0);
	}
	CK(ok == 16u);                       /* KGENOME_EMU_SHIM_MAX: REPORTS (return 0) */
	kgenome_emu_free(e);
}

/* The page budget: a guest touching more pages than cfg.max_pages ends in a FAULT. */
static void emu_pages(void)
{
	static const uint8_t code[] = {
		0x31, 0xff,                              /* xor edi,edi */
		0xbe, 0x00, 0x00, 0x06, 0,               /* mov esi, 0x60000 */
		0xba, 3, 0, 0, 0,                        /* mov edx, 3 */
		0x41, 0xba, 0x22, 0, 0, 0,               /* mov r10d, 0x22 */
		0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,/* mov r8, -1 */
		0x45, 0x31, 0xc9,                        /* xor r9d,r9d */
		0xb8, 9, 0, 0, 0,                        /* mov eax, 9 */
		0x0f, 0x05,                              /* syscall */
		0x48, 0x89, 0xc3,                        /* mov rbx, rax */
		0xb9, 96, 0, 0, 0,                       /* mov ecx, 96 */
		0xc6, 0x03, 0x01,                        /* L: mov byte [rbx],1 */
		0x48, 0x81, 0xc3, 0x00, 0x10, 0, 0,      /* add rbx,0x1000 */
		0xff, 0xc9,                              /* dec ecx */
		0x75, 0xf2                               /* jnz L */
	};
	uint8_t c[128];
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	uint32_t n = sizeof code;

	memcpy(c, code, sizeof code);
	n = emit_exit(c, n);
	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = 200000;
	cfg.max_pages = 40;
	e = kgenome_emu_new(&cfg);
	CK(e != NULL);
	if (!e)
		return;
	CK(kgenome_emu_map(e, ECODE, c, n, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X));
	CK(kgenome_emu_map(e, ESTACK, NULL, 0x1000, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W));
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, ESTACK + 0x800);
	kgenome_emu_set_rip(e, ECODE);
	/* REPORTS: the page budget ends the run as a fault, not as a clean exit */
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_FAULT);
	kgenome_emu_free(e);
}

/* KGENOME_EMU_MAX_VMA (1024): after it mmap says ENOMEM to the guest and to nobody else. */
static void emu_vma_run(unsigned count, uint64_t *refused, int *said)
{
	/* r13d = count ; L: mmap(0,0x1000,PROT_READ,MAP_PRIVATE|ANON,-1,0) ; test rax,rax ;
	 * jns +3 ; inc r12 ; dec r13 ; jnz L ; mov rdi,r12 ; mov eax,60 ; syscall */
	uint8_t code[] = {
		0x4d, 0x31, 0xe4,                        /* xor r12,r12 */
		0x41, 0xbd, 0, 0, 0, 0,                  /* mov r13d,count */
		0x31, 0xff,                              /* L: xor edi,edi */
		0xbe, 0x00, 0x10, 0, 0,                  /* mov esi,0x1000 */
		0xba, 1, 0, 0, 0,                        /* mov edx,1 (PROT_READ) */
		0x41, 0xba, 0x22, 0, 0, 0,               /* mov r10d,0x22 */
		0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,/* mov r8,-1 */
		0x45, 0x31, 0xc9,                        /* xor r9d,r9d */
		0xb8, 9, 0, 0, 0,                        /* mov eax,9 */
		0x0f, 0x05,                              /* syscall */
		0x48, 0x85, 0xc0,                        /* test rax,rax */
		0x79, 0x03,                              /* jns +3 */
		0x49, 0xff, 0xc4,                        /* inc r12 */
		0x49, 0xff, 0xcd,                        /* dec r13 */
		0x75, 0xd0,                              /* jnz L */
		0x4c, 0x89, 0xe7,                        /* mov rdi,r12 */
		0xb8, 0x3c, 0, 0, 0,                     /* mov eax,60 */
		0x0f, 0x05
	};
	struct kgenome_emu *e;
	enum kgenome_emu_stop st;
	uint32_t unk[8];

	p32(code, 5, count);
	*refused = 0;
	*said = 0;
	e = emu_with(code, sizeof code);
	CK(e != NULL);
	if (!e)
		return;
	st = kgenome_emu_run(e);
	*refused = kgenome_emu_get_reg(e, KGENOME_EMU_RDI);
	*said = st != KGENOME_EMU_STOP_EXIT || kgenome_emu_unknown_syscalls(e, unk, 8) > 0u ||
		kgenome_emu_unhandled(e) > 0u;
	kgenome_emu_free(e);
}

static void emu_vma(void)
{
	uint64_t few, many;
	int said_few, said_many;

	emu_vma_run(100, &few, &said_few);
	emu_vma_run(1100, &many, &said_many);
	CK(few == 0u);                               /* the control: 100 mappings all succeed */
	CK(many > 0u);                               /* the ceiling is real: it did refuse */
	KM_CHECK(many == 0u || said_many,
		 "an mmap refused for the live-mapping ceiling is visible to the caller, not only to the guest",
		 "KGENOME_EMU_MAX_VMA emu_mem.c:142 lost: mappings past 1024 are refused (ENOMEM to the guest) with a clean EXIT and no counter");
}

/* The fake kernel32's export list: KGENOME_EMU_UNP_K32_MAX_EXPORTS (192) is a cap on
 * what a guest walking the directory can see; bites only if a module has more APIs. */
static void emu_k32_exports(void)
{
	unsigned m, i, n_api = kgenome_emu_win_api_count();

	for (m = 0; m < kgenome_emu_win_mod_count(); m++) {
		unsigned have = 0;

		for (i = 0; i < n_api; i++)
			have += kgenome_emu_win_api_mod(i) == m;
		CK(have <= 192u);
	}
	/* kernelbase borrows kernel32's list */
}

/* ======================================================================== *
 *  The diagnose scan over a hand-made object                                *
 * ======================================================================== */

static uint8_t dimg[1u << 16];
static struct kgenome_elf_info dinfo;

static void dobj(uint64_t len, struct kgenome_obj *obj)
{
	memset(&dinfo, 0, sizeof dinfo);
	dinfo.version = KGENOME_ELF_INFO_VERSION;
	dinfo.valid = 1;
	dinfo.elf_class = 2;
	dinfo.elf_data = 1;
	dinfo.e_type = KGENOME_ELF_EXEC;
	dinfo.e_machine = 62;
	dinfo.entry_addr = 0x400100;
	dinfo.seg_count = 1;
	dinfo.load_count = 1;
	dinfo.min_vaddr = 0x400000;
	dinfo.max_vaddr = 0x400000 + len;
	dinfo.seg[0].file_off = 0;
	dinfo.seg[0].file_size = len;
	dinfo.seg[0].mem_addr = 0x400000;
	dinfo.seg[0].mem_size = len;
	dinfo.seg[0].type = 1;
	dinfo.seg[0].perm = KGENOME_PERM_R | KGENOME_PERM_X;
	dinfo.seg[0].claim_off = 0;
	dinfo.seg[0].claim_len = len;
	memset(obj, 0, sizeof *obj);
	obj->format = KGENOME_FMT_ELF;
	obj->arch = KGENOME_ARCH_X86_64;
	obj->subtype = KGENOME_ELF_EXEC;
	obj->obj_size = len;
	obj->entry_off = 0x100;
	obj->file_header = &dinfo;
}

static struct kgenome_diag_scan *dscan(uint64_t len)
{
	struct kgenome_obj obj;
	struct kgenome_diag_inputs in;

	dobj(len, &obj);
	memset(&in, 0, sizeof in);
	return kgenome_diag_scan_with_inputs(&obj, dimg, len, KGENOME_DIAG_RUN_SYSCALL, &in);
}

static const struct kgenome_diag_hit *find_cap(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t i;

	for (i = 0; i < kgenome_diag_scan_count(s); i++)
		if (kgenome_diag_scan_at(s, i)->cap == cap)
			return kgenome_diag_scan_at(s, i);
	return NULL;
}

static int linked_from(const struct kgenome_diag_hit *h, uint16_t from)
{
	unsigned i;

	for (i = 0; h && i < h->n_in; i++)
		if (h->in[i].from == from)
			return 1;
	return 0;
}

/*
 * KGENOME_DIAG_ORG_STK (32) diag_origin.c:74: the origin map follows a value through
 * `push` and `pop` for the first 32 stack slots only. mmap's result is pushed AFTER
 * `depth` other pushes and popped into the read's buffer register: within the table the
 * read is linked to the mmap, past it the link is gone - no status, no counter.
 */
static unsigned org_stack_run(unsigned depth, int *linked)
{
	static const uint8_t mm[] = {
		0x31, 0xff,                              /* xor edi,edi        */
		0xbe, 0x00, 0x10, 0, 0,                  /* mov esi,0x1000     */
		0xba, 7, 0, 0, 0,                        /* mov edx,7          */
		0x41, 0xba, 0x22, 0, 0, 0,               /* mov r10d,0x22      */
		0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,/* mov r8,-1          */
		0x45, 0x31, 0xc9,                        /* xor r9d,r9d        */
		0xb8, 9, 0, 0, 0,                        /* mov eax,9          */
		0x0f, 0x05                               /* syscall            */
	};
	static const uint8_t rd[] = {
		0x5e,                                    /* pop rsi            */
		0x31, 0xff,                              /* xor edi,edi        */
		0xba, 0x00, 0x01, 0, 0,                  /* mov edx,0x100      */
		0x31, 0xc0,                              /* xor eax,eax        */
		0x0f, 0x05,                              /* syscall (read)     */
		0xc3
	};
	uint64_t at = 0x100;
	struct kgenome_diag_scan *s;
	const struct kgenome_diag_hit *a, *r;
	unsigned i, n;
	enum kgenome_status st;

	memset(dimg, 0, sizeof dimg);
	memcpy(dimg + at, mm, sizeof mm);
	at += sizeof mm;
	for (i = 0; i < depth; i++)
		dimg[at++] = 0x51;                       /* push rcx */
	dimg[at++] = 0x50;                           /* push rax - the mmap's result */
	memcpy(dimg + at, rd, sizeof rd);
	at += sizeof rd;
	s = dscan(at);
	if (!s) {
		*linked = -1;
		return 0;
	}
	n = kgenome_diag_scan_count(s);
	st = kgenome_diag_scan_status(s);
	a = find_cap(s, KGENOME_NUCLEO_ALLOC_EXEC);
	if (!a)
		a = find_cap(s, KGENOME_NUCLEO_ALLOC);
	r = find_cap(s, KGENOME_NUCLEO_MEM_READ);
	*linked = a && r && linked_from(r, 0);
	kgenome_diag_scan_free(s);
	return n * 8u + (unsigned)st;                /* status folded in: 0 == whole */
}

static void diag_origin_stack(void)
{
	int near_l = 0, deep_l = 0;
	unsigned near_s, deep_s;

	near_s = org_stack_run(3, &near_l);
	deep_s = org_stack_run(40, &deep_l);
	CK(near_l == 1);                             /* the control: the link is made */
	CK(near_s % 8u == 0u);
	{
		int edge = 0;

		(void)org_stack_run(31, &edge);          /* the 32nd slot (index 31) still holds it */
		CK(edge == 1);
		(void)org_stack_run(32, &edge);          /* the 33rd (index 32) does not */
		CK(edge == 0);
	}
	KM_CHECK(deep_l == 1 || deep_s % 8u != 0u,
		 "a value pushed and popped through a deep stack keeps its link to the producing call, or the scan says it is partial",
		 "KGENOME_DIAG_ORG_STK diag_origin.c:74 lost: the producer link of a value pushed past the 32nd stack slot");
}


/*
 * KGENOME_CELL_STACK (16) cell_state.c:36 - the walk's modelled stack drops the OLDEST
 * slot when a push passes 16 ("a walk that stopped there would stop on ordinary code").
 * A syscall number pushed first and popped last, under 16 other pushes, is therefore
 * unknown by the time it is popped. The site is NOT lost: it stays a node, and the node
 * says it was not understood (KGENOME_DIAG_H_OPAQUE, cap NONE) - the signal this checks.
 */
static void cell_stack(void)
{
	unsigned depth, i;

	for (depth = 3; depth <= 20; depth += 17) {
		uint64_t at = 0x100;
		struct kgenome_diag_scan *s;
		const struct kgenome_diag_hit *h;

		memset(dimg, 0, sizeof dimg);
		dimg[at++] = 0x6a; dimg[at++] = 0x09;                /* push 9  */
		for (i = 0; i < depth; i++)
			dimg[at++] = 0x51;                           /* push rcx */
		for (i = 0; i < depth; i++)
			dimg[at++] = 0x59;                           /* pop rcx  */
		dimg[at++] = 0x58;                                   /* pop rax  */
		dimg[at++] = 0x0f; dimg[at++] = 0x05;                /* syscall  */
		dimg[at++] = 0xc3;
		s = dscan(at);
		CK(s != NULL);
		if (!s)
			continue;
		CK(kgenome_diag_scan_count(s) == 1u);
		h = kgenome_diag_scan_at(s, 0);
		if (depth == 3u) {
			CK(h && h->cap == KGENOME_NUCLEO_ALLOC);
		} else {
			/* never silently absent: not understood, and said so on the node */
			CK(h && h->cap == KGENOME_NUCLEO_NONE && (h->bits & KGENOME_DIAG_H_OPAQUE));
		}
		kgenome_diag_scan_free(s);
	}
}


/* ======================================================================== *
 *  Rebuilding an ELF out of emulated memory                                  *
 * ======================================================================== */

static uint8_t rb_mem[0x4000];
static uint64_t rb_hole_lo, rb_hole_hi;

static int rb_rd(void *user, uint64_t va, void *dst, uint32_t n)
{
	(void)user;
	if (va < 0x400000u || va - 0x400000u + n > sizeof rb_mem)
		return 0;
	if (va < rb_hole_hi && va + n > rb_hole_lo)
		return 0;
	memcpy(dst, rb_mem + (va - 0x400000u), n);
	return 1;
}

/*
 * elf_rebuild.c:155 - "A segment that cannot be read is left as the zeroes calloc gave,
 * rather than failing the whole rebuild". The rebuilt file then holds a segment of zeros
 * INSIDE the span it reports as covered (covered_lo/hi are the min and max of the
 * segments that WERE read), so a caller cannot tell the hole from content. Reported
 * [Inference] as low severity: the guest memory the read failed on was never mapped.
 */
static void elf_rebuild_hole(void)
{
	uint8_t *out = NULL;
	uint64_t len = 0, lo = 0, hi = 0, ph = 64;
	unsigned i;
	int rc;

	memset(rb_mem, 0, sizeof rb_mem);
	memcpy(rb_mem, "\177ELF\2\1\1", 7);
	p16(rb_mem, 16, 2);
	p16(rb_mem, 18, 62);
	p32(rb_mem, 20, 1);
	p64(rb_mem, 24, 0x400100);
	p64(rb_mem, 32, ph);
	p16(rb_mem, 52, 64);
	p16(rb_mem, 54, 56);
	p16(rb_mem, 56, 3);
	for (i = 0; i < 3u; i++) {
		uint64_t at = ph + 56u * i, off = 0x1000u * i;

		p32(rb_mem, at, 1);
		p32(rb_mem, at + 4, 5);
		p64(rb_mem, at + 8, off);
		p64(rb_mem, at + 16, 0x400000u + off);
		p64(rb_mem, at + 24, 0x400000u + off);
		p64(rb_mem, at + 32, i ? 0x100u : 0x200u);
		p64(rb_mem, at + 40, i ? 0x100u : 0x200u);
		p64(rb_mem, at + 48, 0x1000);
		if (i)
			memset(rb_mem + off, 0xaa, 0x100);
	}
	rb_hole_lo = rb_hole_hi = 0;
	rc = kgenome_elf_rebuild(0x400000, rb_rd, NULL, 0, &out, &len, &lo, &hi);
	CK(rc == 1 && out && len == 0x2100u);
	CK(out && out[0x1000] == 0xaau);             /* the control: every segment readable */
	CK(lo == 0x400000u && hi == 0x402100u);
	free(out);

	rb_hole_lo = 0x401000;
	rb_hole_hi = 0x401100;                       /* the middle segment cannot be read */
	rc = kgenome_elf_rebuild(0x400000, rb_rd, NULL, 0, &out, &len, &lo, &hi);
	CK(rc == 1 && out && len == 0x2100u);
	KM_CHECK(!(rc == 1 && out && out[0x1000] == 0u && lo <= 0x401000u && hi >= 0x401100u),
		 "a segment that could not be read back is not presented as zero bytes inside the covered span",
		 "elf_rebuild.c:155 lost: the contents of a PT_LOAD the emulated memory could not be read for (zero-filled, covered range still spans it) [Inference: low]");
	free(out);
}


/* ======================================================================== *
 *  The relocatable-object emulate route: tokens and remembered values       *
 * ======================================================================== */

static uint8_t kmod[1u << 16];
static struct kgenome_elf_info kinfo;

/*
 * ET_REL x86-64 with one function `f` (a sized STT_FUNC) of `n_fill` + 1 calls to
 * malloc, the last one's result stored through rbx and read back into rsi, then a call
 * to write. The value reaches `write` through MEMORY, which only the emulate route
 * follows: the static route's origin map has no memory.
 */
static uint64_t kmod_build(unsigned n_fill, unsigned fill_sym, uint64_t *len_out)
{
	static const char shs[] = "\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab";
	static const char strs[] = "\0malloc\0write\0f";
	const uint64_t text = 0x200;
	uint64_t rela, sym, str, shstr, sh, n = 0, nrel = 0, code_n;
	unsigned i;
	uint8_t *c = kmod + text;

	memset(kmod, 0, sizeof kmod);
	c[n++] = 0x53;                                   /* push rbx           */
	c[n++] = 0x48; c[n++] = 0x8d; c[n++] = 0x5c; c[n++] = 0x24; c[n++] = 0xc0; /* lea rbx,[rsp-0x40] */
	/* the relocations are recorded as offsets of the displacement */
	rela = 0x4000;
	for (i = 0; i <= n_fill; i++) {
		c[n++] = 0xe8;
		p64(kmod, rela + 24u * nrel, n);                       /* r_offset (section relative) */
		/* the n_fill fillers call fill_sym; the last call is always malloc */
		p64(kmod, rela + 24u * nrel + 8u,
		    ((uint64_t)(i < n_fill ? fill_sym : 1u) << 32) | 4u);
		p64(kmod, rela + 24u * nrel + 16u, (uint64_t)-4);      /* addend */
		nrel++;
		n += 4;
	}
	c[n++] = 0x48; c[n++] = 0x89; c[n++] = 0x03;       /* mov [rbx],rax      */
	c[n++] = 0x48; c[n++] = 0x8b; c[n++] = 0x33;       /* mov rsi,[rbx]      */
	c[n++] = 0xe8;
	p64(kmod, rela + 24u * nrel, n);
	p64(kmod, rela + 24u * nrel + 8u, (2ull << 32) | 4u);      /* sym 2 write */
	p64(kmod, rela + 24u * nrel + 16u, (uint64_t)-4);
	nrel++;
	n += 4;
	c[n++] = 0x5b;                                   /* pop rbx            */
	c[n++] = 0xc3;
	code_n = n;

	sym = rela + 24u * nrel + 16u;
	str = sym + 24u * 4u + 16u;
	shstr = str + sizeof strs + 16u;
	sh = (shstr + sizeof shs + 16u + 15u) & ~(uint64_t)15u;
	memcpy(kmod + str, strs, sizeof strs);
	memcpy(kmod + shstr, shs, sizeof shs);
	/* symbols: 1 malloc, 2 write (undefined FUNC), 3 f (defined, sized) */
	p32(kmod, sym + 24u * 1u, 1);  kmod[sym + 24u * 1u + 4u] = 0x12;
	p32(kmod, sym + 24u * 2u, 8);  kmod[sym + 24u * 2u + 4u] = 0x12;
	p32(kmod, sym + 24u * 3u, 14); kmod[sym + 24u * 3u + 4u] = 0x12;
	p16(kmod, sym + 24u * 3u + 6u, 1);               /* shndx = .text */
	p64(kmod, sym + 24u * 3u + 8u, 0);               /* value */
	p64(kmod, sym + 24u * 3u + 16u, code_n);         /* size  */

	memcpy(kmod, "\177ELF\2\1\1", 7);
	p16(kmod, 16, 1);
	p16(kmod, 18, 62);
	p32(kmod, 20, 1);
	p64(kmod, 40, sh);
	p16(kmod, 52, 64);
	p16(kmod, 58, 64);
	p16(kmod, 60, 6);
	p16(kmod, 62, 5);
	{
		const struct { uint32_t name, type; uint64_t flags, off, size; } t[] = {
			{ 0,  0, 0, 0, 0 },
			{ 1,  1, 6, text, code_n },
			{ 7,  4, 0, rela, 24u * nrel },
			{ 18, 2, 0, sym, 24u * 4u },
			{ 26, 3, 0, str, sizeof strs },
			{ 34, 3, 0, shstr, sizeof shs }
		};

		for (i = 0; i < 6u; i++) {
			uint64_t at = sh + 64u * i;

			p32(kmod, at, t[i].name);
			p32(kmod, at + 4, t[i].type);
			p64(kmod, at + 8, t[i].flags);
			p64(kmod, at + 24, t[i].off);
			p64(kmod, at + 32, t[i].size);
			p32(kmod, at + 40, i == 3u ? 4u : 0u);
			p64(kmod, at + 56, i == 3u ? 24u : 0u);
		}
	}
	*len_out = sh + 6u * 64u;
	return *len_out;
}

/* Is `write` linked to the LAST malloc? status folded in the low bits. */
static unsigned kmod_run(unsigned n_fill, unsigned fill_sym, int *linked, unsigned *n_nodes)
{
	struct kgenome_obj obj;
	struct kgenome_diag_inputs in;
	struct kgenome_diag_scan *s;
	uint64_t len;
	const struct kgenome_diag_hit *w;
	unsigned st;

	kmod_build(n_fill, fill_sym, &len);
	memset(&obj, 0, sizeof obj);
	*linked = -1;
	*n_nodes = 0;
	if (!kgenome_elf_image_parse(kof_buf_make(kmod, len), &kinfo, &obj))
		return 99;
	memset(&in, 0, sizeof in);
	s = kgenome_diag_scan_with_inputs(&obj, kmod, len,
					  KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_EMULATE, &in);
	if (!s)
		return 98;
	*n_nodes = kgenome_diag_scan_count(s);
	st = (unsigned)kgenome_diag_scan_status(s);
	*linked = 0;
	/* the LAST node is the write at the end of the function */
	w = kgenome_diag_scan_at(s, kgenome_diag_scan_count(s) - 1u);
	if (w && w->cap == KGENOME_NUCLEO_MEM_WRITE)
		*linked = linked_from(w, (uint16_t)n_fill);
	kgenome_diag_scan_free(s);
	return st;
}

static void diag_rel_tables(void)
{
	int lin = -1;
	unsigned nodes = 0, st;

	/* the control: a few producers, the value through memory is followed */
	st = kmod_run(3, 1, &lin, &nodes);
	CK(nodes == 5u);                            /* four mallocs and the write */
	CK(lin == 1);
	CK(st == (unsigned)KGENOME_OK);

	/*
	 * KGENOME_DIAG_REL_SEEN (64) diag_emu_sites.c:395,464: one span remembers 64
	 * (value, node) pairs. The 65th producer of a function is not remembered, so a
	 * consumer that reads its result back through memory is not linked to it - and
	 * nothing says the table was full. (The 64th still is: the boundary below.)
	 */
	st = kmod_run(62, 1, &lin, &nodes);
	CK(lin == 1 && st == (unsigned)KGENOME_OK);
	st = kmod_run(64, 1, &lin, &nodes);
	KM_CHECK(lin == 1 || st != (unsigned)KGENOME_OK,
		 "a value produced by the 65th call of a function and read back through memory is linked to its producer, or the scan says it is partial",
		 "KGENOME_DIAG_REL_SEEN diag_emu_sites.c:464 lost: the link from any producer past the 64th value remembered in one function (relocatable object)");

	/*
	 * KGENOME_DIAG_TOK_SPAN (256) diag_emu_sites.c:457: a token is a page of the arena
	 * indexed by the NODE, and only the first 256 nodes can have one. Fillers here are
	 * calls that produce nothing (write), so the remembered-values table is not the
	 * limit: the producer's node index is.
	 */
	st = kmod_run(200, 2, &lin, &nodes);
	CK(lin == 1 && st == (unsigned)KGENOME_OK);
	st = kmod_run(254, 2, &lin, &nodes);
	CK(lin == 1 && st == (unsigned)KGENOME_OK);
	st = kmod_run(256, 2, &lin, &nodes);
	CK(lin == 0 && st == (unsigned)KGENOME_OK);
	st = kmod_run(300, 2, &lin, &nodes);
	KM_CHECK(lin == 1 || st != (unsigned)KGENOME_OK,
		 "a value produced by node 300 and read back through memory is linked to its producer, or the scan says it is partial",
		 "KGENOME_DIAG_TOK_SPAN diag_emu_sites.c:457 lost: the link from any producer whose node index is >= 256 (relocatable object)");
}


/* ======================================================================== *
 *  The PE self-resolve route                                                *
 * ======================================================================== */

/*
 * A PE whose entry code is `code`, scanned by the API-hash route alone. Returns the
 * scan's status; *selfres is how many SELF_RESOLVE nodes it made, *ran whether the
 * route ran at all.
 */
static unsigned pe_resolve_run(const uint8_t *code, uint32_t n, unsigned *selfres)
{
	struct kgenome_obj obj;
	struct kgenome_diag_inputs in;
	struct kgenome_diag_scan *s;
	unsigned st, i;

	pe_base(1, NULL);
	memcpy(pe_a + RAW(0x1000), code, n);
	*selfres = 0;
	memset(&obj, 0, sizeof obj);
	if (!kgenome_pe_image_parse(kof_buf_make(pe_a, sizeof pe_a), &pe_info, &obj))
		return 99;
	memset(&in, 0, sizeof in);
	s = kgenome_diag_scan_with_inputs(&obj, pe_a, sizeof pe_a, KGENOME_DIAG_RUN_APIHASH, &in);
	if (!s)
		return 98;
	st = (unsigned)kgenome_diag_scan_status(s);
	for (i = 0; i < kgenome_diag_scan_count(s); i++)
		*selfres += kgenome_diag_scan_at(s, i)->cap == KGENOME_NUCLEO_SELF_RESOLVE;
	kgenome_diag_scan_free(s);
	return st;
}

static void diag_pe_resolve(void)
{
	/* mov rax, gs:[0x60] ; <pad nops> ; mov rax,[rax+0x18] ; ... */
	static const uint8_t peb[] = { 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0 };
	static const uint8_t ldr[] = { 0x48, 0x8b, 0x40, 0x18 };
	uint8_t code[128];
	unsigned n, self, st, pad;

	/* the control: the walk is read straight on - the route finds it and runs */
	n = 0;
	memcpy(code + n, peb, sizeof peb);   n += sizeof peb;
	memcpy(code + n, ldr, sizeof ldr);   n += sizeof ldr;
	code[n++] = 0xc3;
	st = pe_resolve_run(code, n, &self);
	CK(self == 1u);
	CK(st == (unsigned)KGENOME_OK);

	/*
	 * PEB_TTL (8) diag_apihash.c:59 - the load of PEB.Ldr must follow the PEB read
	 * within 8 instructions or the walk is not recognised and the resolver is not
	 * run. `nop`s between them are all it takes, and nothing says a PEB read was
	 * seen and not followed: the scan is whole and has no self-resolve node.
	 */
	for (pad = 0; pad < 8u; pad += 7u) {
		n = 0;
		memcpy(code + n, peb, sizeof peb);   n += sizeof peb;
		memset(code + n, 0x90, pad);         n += pad;
		memcpy(code + n, ldr, sizeof ldr);   n += sizeof ldr;
		code[n++] = 0xc3;
		st = pe_resolve_run(code, n, &self);
		CK(self == 1u);                  /* within the window: still found */
	}
	n = 0;
	memcpy(code + n, peb, sizeof peb);   n += sizeof peb;
	memset(code + n, 0x90, 12);          n += 12;
	memcpy(code + n, ldr, sizeof ldr);   n += sizeof ldr;
	code[n++] = 0xc3;
	st = pe_resolve_run(code, n, &self);
	KM_CHECK(self == 1u || st != (unsigned)KGENOME_OK,
		 "a PEB read followed by the Ldr load 12 instructions later is a self-resolving program, or the scan says it did not look further",
		 "PEB_TTL diag_apihash.c:59 lost: the self-resolve node of a program that pads more than 8 instructions between the PEB read and the Ldr load");

	/*
	 * A run that ends in a FAULT (the guest dereferences null after the walk) sets no
	 * status: diag_emu_image.c:240 documents "faults where a stager would" as an ORDINARY
	 * ending, so this is the stated design and not a miss. It is asserted so a change to
	 * it is a decision: the SELF_RESOLVE node is still made and the scan stays whole.
	 */
	n = 0;
	memcpy(code + n, peb, sizeof peb);   n += sizeof peb;
	memcpy(code + n, ldr, sizeof ldr);   n += sizeof ldr;
	code[n++] = 0x31; code[n++] = 0xc0;                      /* xor eax,eax  */
	code[n++] = 0x48; code[n++] = 0x8b; code[n++] = 0x00;    /* mov rax,[rax] */
	code[n++] = 0xc3;
	st = pe_resolve_run(code, n, &self);
	CK(self == 1u);
	CK(st == (unsigned)KGENOME_OK);
}


/*
 * KGENOME_EMU_EXEC_WATCH from an OBJECT: a PE of `nsec` code sections, each jumping to the
 * next, run by the unpacker's own entry (kgenome_emu_unp_run_pe). pe_set_run_state adds
 * every section as a hop stage; the table holds 16.
 */
static uint8_t pe_many[0x800u + 0x1000u * 24u];

static void emu_pe_sections(void)
{
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	struct kgenome_emu_unp_report rep;
	struct kgenome_budget bud;
	struct kgenome_emu *em;
	unsigned nsec, k;
	uint64_t rip = 0;
	uint32_t hops = 0;

	for (nsec = 16; nsec <= 20; nsec += 4) {
		memset(pe_many, 0, sizeof pe_many);
		pe_many[0] = 'M'; pe_many[1] = 'Z';
		p32(pe_many, 0x3c, 0x80);
		memcpy(pe_many + 0x80, "PE\0\0", 4);
		p16(pe_many, 0x84, 0x8664);
		p16(pe_many, 0x86, (uint16_t)nsec);
		p16(pe_many, 0x94, 0xf0);
		p16(pe_many, 0x96, 0x22);
		p16(pe_many, 0x98, 0x20b);
		p32(pe_many, 0x98 + 16, 0x1000);
		p64(pe_many, 0x98 + 24, 0x140000000ull);
		p32(pe_many, 0x98 + 32, 0x1000);
		p32(pe_many, 0x98 + 36, 0x200);
		p32(pe_many, 0x98 + 56, 0x1000u * (nsec + 1u));
		p32(pe_many, 0x98 + 60, 0x800);
		p32(pe_many, 0x98 + 108, 16);
		for (k = 0; k < nsec; k++) {
			uint64_t at = 0x188u + 40u * k, raw = 0x800u + 0x1000u * k;

			memcpy(pe_many + at, ".text", 5);
			p32(pe_many, at + 8, 0x1000);
			p32(pe_many, at + 12, 0x1000u * (k + 1u));
			p32(pe_many, at + 16, 0x1000);
			p32(pe_many, at + 20, (uint32_t)raw);
			p32(pe_many, at + 36, 0xe0000020u);
			if (k + 1u < nsec) {
				pe_many[raw] = 0xe9;                 /* jmp next section */
				p32(pe_many, raw + 1, 0x1000u - 5u);
			} else {
				pe_many[raw] = 0xc3;
			}
		}
		memset(&obj, 0, sizeof obj);
		CK(kgenome_pe_image_parse(kof_buf_make(pe_many, 0x800u + 0x1000u * nsec), &info, &obj));
		CK(info.sec_count == nsec);
		memset(&bud, 0, sizeof bud);
		bud.max_insn = 100000;
		memset(&rep, 0, sizeof rep);
		em = kgenome_emu_unp_run_pe(&(const struct kgenome_emu_unp_pe_req){
			.file = pe_many, .n = 0x800u + 0x1000u * nsec, .info = &info,
			.imports = NULL, .bud = &bud, .idle = 0, .hand_back = 0,
			.extensions = 0u, .oep = NULL, .n_oep = 0, .decl = NULL, .rep = &rep,
		});
		CK(em != NULL);
		if (!em)
			continue;
		kgenome_emu_last_hop(em, &rip, &hops);
		if (nsec == 16u)
			CK(hops == 15u);                     /* every section but the entry's */
		else
			KM_CHECK(hops == nsec - 1u,
				 "every section a packed PE's run enters is a hop stage (snapshot), or the table's overflow is signalled",
				 "KGENOME_EMU_EXEC_WATCH emu_unpack_pe.c:375 lost: hop stages of sections past the 16th of a PE ([Inference] a PE with debug sections can exceed 16)");
		kgenome_emu_free(em);
	}
}


/*
 * A relocatable object whose one function calls kallsyms_lookup_name with a NUL-terminated
 * name of `len` identifier characters that sits in .text after the function. What the
 * call was given is read out of the emulated image and kept in the scan (kgenome_diag_str_*).
 */
static unsigned klk_run(unsigned len, uint32_t *kept, uint32_t *refused)
{
	static const char shs[] = "\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab";
	static const char strs[] = "\0kallsyms_lookup_name\0f";
	const uint64_t text = 0x200, rela = 0x1000, sym = 0x1100, str = 0x1200, shstr = 0x1300, sh = 0x1400;
	const uint32_t code_n = 15;
	struct kgenome_obj obj;
	struct kgenome_diag_inputs in;
	struct kgenome_diag_scan *s;
	uint8_t *c = kmod + text;
	uint64_t total = code_n + len + 1u;
	unsigned st, i;

	memset(kmod, 0, sizeof kmod);
	c[0] = 0x53;
	c[1] = 0x48; c[2] = 0x8d; c[3] = 0x3d;
	p32(c, 4, 7);                                    /* lea rdi,[rip+7] -> offset 15 */
	c[8] = 0xe8;
	c[13] = 0x5b;
	c[14] = 0xc3;
	for (i = 0; i < len; i++)
		c[code_n + i] = (uint8_t)('a' + i % 26u);
	p64(kmod, rela, 9);                              /* the displacement of the call */
	p64(kmod, rela + 8, (1ull << 32) | 4u);
	p64(kmod, rela + 16, (uint64_t)-4);
	p32(kmod, sym + 24u, 1);  kmod[sym + 24u + 4u] = 0x12;
	p32(kmod, sym + 48u, 21); kmod[sym + 48u + 4u] = 0x12;
	p16(kmod, sym + 48u + 6u, 1);
	p64(kmod, sym + 48u + 16u, code_n);
	memcpy(kmod + str, strs, sizeof strs);
	memcpy(kmod + shstr, shs, sizeof shs);
	memcpy(kmod, "\177ELF\2\1\1", 7);
	p16(kmod, 16, 1);
	p16(kmod, 18, 62);
	p32(kmod, 20, 1);
	p64(kmod, 40, sh);
	p16(kmod, 52, 64);
	p16(kmod, 58, 64);
	p16(kmod, 60, 6);
	p16(kmod, 62, 5);
	{
		const struct { uint32_t name, type; uint64_t flags, off, size; } t[] = {
			{ 0,  0, 0, 0, 0 },
			{ 1,  1, 6, text, total },
			{ 7,  4, 0, rela, 24 },
			{ 18, 2, 0, sym, 72 },
			{ 26, 3, 0, str, sizeof strs },
			{ 34, 3, 0, shstr, sizeof shs }
		};

		for (i = 0; i < 6u; i++) {
			uint64_t at = sh + 64u * i;

			p32(kmod, at, t[i].name);
			p32(kmod, at + 4, t[i].type);
			p64(kmod, at + 8, t[i].flags);
			p64(kmod, at + 24, t[i].off);
			p64(kmod, at + 32, t[i].size);
			p32(kmod, at + 40, i == 3u ? 4u : 0u);
			p64(kmod, at + 56, i == 3u ? 24u : 0u);
		}
	}
	memset(&obj, 0, sizeof obj);
	if (!kgenome_elf_image_parse(kof_buf_make(kmod, sh + 6u * 64u), &kinfo, &obj))
		return 99;
	memset(&in, 0, sizeof in);
	s = kgenome_diag_scan_with_inputs(&obj, kmod, sh + 6u * 64u,
					  KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_EMULATE, &in);
	if (!s)
		return 98;
	st = (unsigned)kgenome_diag_scan_status(s);
	*kept = kgenome_diag_str_count(s, KGENOME_NUCLEO_KSYM_LOOKUP);
	*refused = kgenome_diag_scan_refused(s);
	kgenome_diag_scan_free(s);
	return st;
}

static void diag_guest_name(void)
{
	uint32_t kept = 0, refused = 0;
	unsigned st;

	st = klk_run(40, &kept, &refused);
	CK(kept == 1u && refused == 0u && st == (unsigned)KGENOME_OK);   /* the control */
	st = klk_run(256, &kept, &refused);
	CK(kept == 1u);                                  /* KGENOME_DIAG_STR_MAX is 256: whole */
	/*
	 * kgenome_diag_emu_guest_name diag_emu_image.c:88 - a name past KGENOME_DIAG_STR_MAX
	 * read out of the guest is "too long to be a symbol" and returns 0: not kept, not
	 * counted in kgenome_diag_scan_refused, no status. (The same name arriving at
	 * kgenome_diag_str_add is refused AND said.)
	 */
	st = klk_run(300, &kept, &refused);
	KM_CHECK(kept == 1u || refused > 0u || st != (unsigned)KGENOME_OK,
		 "a 300-byte name handed to a kernel resolver is kept, or refused and counted, or the scan says it is partial",
		 "KGENOME_DIAG_STR_MAX diag_emu_image.c:88 lost: a name over 256 bytes read from the emulated guest (no refused count, no status; kgenome_diag_str_add itself does report)");
}

int main(void)
{
	elf_limits();
	elf_reloc_names();
	pe_exports();
	pe_imports();
	pe_sections();
	pe_layout_order();
	elf_rebuild_hole();
	funcs_remap();
	xref_tables();
	xref_regions();
	emu_ranges();
	emu_insn_watch();
	emu_snapshots();
	emu_shims();
	emu_pages();
	emu_vma();
	emu_k32_exports();
	diag_origin_stack();
	cell_stack();
	diag_rel_tables();
	diag_pe_resolve();
	emu_pe_sections();
	diag_guest_name();
	printf("genome silent_loss_genome: %s (%u known-miss)\n",
	       fails || km_failed() ? "FAILED" : "ok", km_known());
	return fails != 0 || km_failed();
}
