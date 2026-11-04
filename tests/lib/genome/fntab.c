/*
 * fntab - the function table of an object (libgenome/genotype/image/fntab.h, phenotype/fntab_build.c), case by case.
 *
 * Every object here is BUILT IN MEMORY by the writer below, from the values the test names, so a reader sees the case next to its check. Each row names the
 * case it is for (the selector's decision table, fntab_select.c). RED means: the row fails on the tree before the function table (base): the rows that use only
 * the old API (kgenome_diag_funcs_of, kgenome_funcs_build) are the ones compiled against base to show it (build with -DFNTAB_OLD_API_ONLY).
 *
 * Why the old tests missed what these catch: (a) the IFUNC / NOTYPE / size-0 / Thumb branches of the symbol builder never ran (no fixture had such a symbol);
 * (b) the entry cut ran with an end only at a segment's end, never with padding in front of the next entry or a .rodata behind the last function; (c)
 * api_image t_funcs checked "the cut is where the entries say", not that a cut at a padding byte is wrong.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#ifndef FNTAB_OLD_API_ONLY
#include <genotype/image/fntab.h>
#endif
#include <phenotype/diag_scan.h>
#include <phenotype/diag_private.h>        /* kgenome_diag_extent: the one code extent */

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* ---- the writer ------------------------------------------------------------------------------------------------ */

#define TEXT_OFF 0x100u
#define MAXB 0x4000u

struct sym { const char *name; uint64_t value, size; uint8_t info; uint16_t shndx; };

struct elf_in {
	int c64, be;
	uint16_t em;
	uint64_t base;                  /* the address of file offset 0 */
	const uint8_t *text;
	uint32_t text_n;
	uint32_t rodata_n;              /* bytes of .rodata behind .text inside the segment */
	const uint8_t *eh;              /* raw .eh_frame, built for lay.eh_va */
	uint32_t eh_n;
	int sections;                   /* 1: a section table */
	int eh_hdr;                     /* 1: PT_GNU_EH_FRAME + the search header */
	const struct sym *sym;
	unsigned nsym;
	int dyn;                        /* the symbols go to .dynsym */
	int eh_section;                 /* 1: .eh_frame is a section (needs sections) */
	const uint8_t *got;             /* raw .got words, placed at lay.got_va (needs sections); CN-5's mips_gp_of reads this section by name */
	uint32_t got_n;
};

struct lay { uint32_t ro_off, got_off, eh_off, hdr_off, seg_end; uint64_t eh_va, got_va, text_va; };

static uint32_t al(uint32_t v, uint32_t a) { return (v + a - 1u) & ~(a - 1u); }

static void layout(const struct elf_in *in, struct lay *l)
{
	l->ro_off = al(TEXT_OFF + in->text_n, 4u);
	l->got_off = al(l->ro_off + in->rodata_n, 4u);
	l->eh_off = al(l->got_off + in->got_n, 8u);
	l->hdr_off = al(l->eh_off + in->eh_n, 4u);
	l->seg_end = l->hdr_off + (in->eh_hdr ? 16u : 0u);
	l->eh_va = in->base + l->eh_off;
	l->got_va = in->base + l->got_off;
	l->text_va = in->base + TEXT_OFF;
}

struct wr { uint8_t *b; int be; };
static void p16(struct wr *w, uint32_t at, uint32_t v) { w->b[at + (w->be ? 1u : 0u)] = (uint8_t)v; w->b[at + (w->be ? 0u : 1u)] = (uint8_t)(v >> 8); }
static void p32(struct wr *w, uint32_t at, uint32_t v) { int i; for (i = 0; i < 4; i++) w->b[at + (w->be ? 3 - i : i)] = (uint8_t)(v >> (8 * i)); }
static void p64(struct wr *w, uint32_t at, uint64_t v) { int i; for (i = 0; i < 8; i++) w->b[at + (w->be ? 7 - i : i)] = (uint8_t)(v >> (8 * i)); }
static void pw(struct wr *w, int c64, uint32_t at, uint64_t v) { if (c64) p64(w, at, v); else p32(w, at, (uint32_t)v); }

/* Builds the file into `out` (MAXB bytes) and returns its size. */
static uint32_t elf_build(const struct elf_in *in, uint8_t *out)
{
	struct wr w = { out, in->be };
	struct lay l;
	const int c64 = in->c64;
	const uint32_t ehsz = c64 ? 64u : 52u, phsz = c64 ? 56u : 32u, shsz = c64 ? 64u : 40u, symsz = c64 ? 24u : 16u;
	uint32_t n = 0, phn = 1u + (in->eh_hdr ? 1u : 0u), ph = ehsz, sh = 0, shn = 0, i;
	uint32_t symtab_off = 0, strtab_off = 0, shstr_off = 0, symtab_n = 0, strtab_n = 0, shstr_n = 0;
	char strtab[512], shstr[128];

	memset(out, 0, MAXB);
	layout(in, &l);
	out[0] = 0x7f; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
	out[4] = c64 ? 2 : 1; out[5] = in->be ? 2 : 1; out[6] = 1;
	p16(&w, 16, 2);                         /* ET_EXEC */
	p16(&w, 18, in->em);
	p32(&w, 20, 1);
	pw(&w, c64, 24, in->base + TEXT_OFF);   /* the entry point: the first byte of .text */
	pw(&w, c64, 28 + (c64 ? 4u : 0u), ph);  /* e_phoff */
	p16(&w, c64 ? 52 : 40, ehsz);
	p16(&w, c64 ? 54 : 42, phsz);
	p16(&w, c64 ? 56 : 44, phn);
	/* the segment: everything up to the end of the unwind data, R X */
	if (c64) {
		p32(&w, ph, 1); p32(&w, ph + 4, 5); p64(&w, ph + 8, 0); p64(&w, ph + 16, in->base); p64(&w, ph + 24, in->base);
		p64(&w, ph + 32, l.seg_end); p64(&w, ph + 40, l.seg_end); p64(&w, ph + 48, 0x1000);
	} else {
		p32(&w, ph, 1); p32(&w, ph + 4, 0); p32(&w, ph + 8, (uint32_t)in->base); p32(&w, ph + 12, (uint32_t)in->base);
		p32(&w, ph + 16, l.seg_end); p32(&w, ph + 20, l.seg_end); p32(&w, ph + 24, 5); p32(&w, ph + 28, 0x1000);
	}
	if (in->eh_hdr) {
		const uint32_t p2 = ph + phsz, hv = l.hdr_off;
		const uint64_t hva = in->base + hv;
		if (c64) {
			p32(&w, p2, 0x6474e550u); p32(&w, p2 + 4, 4); p64(&w, p2 + 8, hv); p64(&w, p2 + 16, hva); p64(&w, p2 + 24, hva);
			p64(&w, p2 + 32, 16); p64(&w, p2 + 40, 16); p64(&w, p2 + 48, 4);
		} else {
			p32(&w, p2, 0x6474e550u); p32(&w, p2 + 4, hv); p32(&w, p2 + 8, (uint32_t)hva); p32(&w, p2 + 12, (uint32_t)hva);
			p32(&w, p2 + 16, 16); p32(&w, p2 + 20, 16); p32(&w, p2 + 24, 4); p32(&w, p2 + 28, 4);
		}
		/* version 1, eh_frame_ptr pcrel sdata4, fde_count udata4, table datarel sdata4; the pointer is relative to the field at hv + 4 */
		out[hv] = 1; out[hv + 1] = 0x1b; out[hv + 2] = 0x03; out[hv + 3] = 0x3b;
		p32(&w, hv + 4, (uint32_t)(l.eh_va - (hva + 4u)));
		p32(&w, hv + 8, 0);
	}
	memcpy(out + TEXT_OFF, in->text, in->text_n);
	for (i = 0; i < in->rodata_n; i++)
		out[l.ro_off + i] = (uint8_t)(0x41u + i % 26u);                 /* strings: not code */
	if (in->got_n)
		memcpy(out + l.got_off, in->got, in->got_n);
	if (in->eh_n)
		memcpy(out + l.eh_off, in->eh, in->eh_n);
	n = l.seg_end;
	if (!in->sections)
		return n;
	/* .symtab/.dynsym, .strtab, .shstrtab, then the section table: null .text .rodata .eh_frame [.symtab .strtab] .shstrtab */
	{
		uint32_t k, nm = 1;

		strtab[0] = 0;
		strtab_n = 1;
		for (k = 0; k < in->nsym; k++) {
			size_t ln = strlen(in->sym[k].name) + 1u;
			memcpy(strtab + strtab_n, in->sym[k].name, ln);
			strtab_n += (uint32_t)ln;
		}
		symtab_n = (in->nsym + 1u) * symsz;
		if (in->nsym) {
			symtab_off = al(n, 8u);
			n = symtab_off + symtab_n;
			strtab_off = n;
			memcpy(out + n, strtab, strtab_n);
			n += strtab_n;
			nm = 0;
			strtab_n = 1;
			for (k = 0; k < in->nsym; k++) {
				const struct sym *s = &in->sym[k];
				uint32_t o = symtab_off + (k + 1u) * symsz;

				p32(&w, o, strtab_n);
				if (c64) {
					out[o + 4] = s->info; p16(&w, o + 6, s->shndx); p64(&w, o + 8, s->value); p64(&w, o + 16, s->size);
				} else {
					p32(&w, o + 4, (uint32_t)s->value); p32(&w, o + 8, (uint32_t)s->size); out[o + 12] = s->info; p16(&w, o + 14, s->shndx);
				}
				strtab_n += (uint32_t)strlen(s->name) + 1u;
			}
		}
		(void)nm;
		memcpy(shstr, "\0.text\0.rodata\0.eh_frame\0.symtab\0.strtab\0.shstrtab\0.dynsym\0.got\0", 64);
		shstr_n = 64;
		shstr_off = n;
		memcpy(out + n, shstr, shstr_n);
		n += shstr_n;
		sh = al(n, 8u);
		/* names: .text 1, .rodata 7, .eh_frame 15, .symtab 25, .strtab 33, .shstrtab 41, .dynsym 51 */
		{
			uint32_t idx = 0;
#define SEC(name, type, flags, addr, off, size, link, entsz) do { \
	uint32_t o_ = sh + idx * shsz; \
	p32(&w, o_, name); p32(&w, o_ + 4, type); \
	if (c64) { p64(&w, o_ + 8, flags); p64(&w, o_ + 16, addr); p64(&w, o_ + 24, off); p64(&w, o_ + 32, size); p32(&w, o_ + 40, link); p64(&w, o_ + 56, entsz); } \
	else { p32(&w, o_ + 8, (uint32_t)(flags)); p32(&w, o_ + 12, (uint32_t)(addr)); p32(&w, o_ + 16, off); p32(&w, o_ + 20, size); p32(&w, o_ + 24, link); p32(&w, o_ + 36, entsz); } \
	idx++; } while (0)
			SEC(0, 0, 0, 0, 0, 0, 0, 0);
			SEC(1, 1, 6, in->base + TEXT_OFF, TEXT_OFF, in->text_n, 0, 0);
			SEC(7, 1, 2, in->base + l.ro_off, l.ro_off, in->rodata_n ? in->rodata_n : 1u, 0, 0);
			if (in->got_n)
				SEC(59, 1, 3, l.got_va, l.got_off, in->got_n, 0, 0);   /* PROGBITS, WA - CN-5's mips_gp_of finds it by name */
			SEC(15, in->eh_section ? 1 : 0, 2, l.eh_va, l.eh_off, in->eh_section ? in->eh_n : 0u, 0, 0);   /* type 0: the slot is kept (the indices) and is no .eh_frame */
			if (in->nsym) {
				const uint32_t strx = idx + 1u;
				SEC(in->dyn ? 51 : 25, in->dyn ? 11 : 2, in->dyn ? 2 : 0, 0, symtab_off, symtab_n, strx, symsz);
				SEC(33, 3, 0, 0, strtab_off, strtab_n, 0, 0);
			}
			SEC(41, 3, 0, 0, shstr_off, shstr_n, 0, 0);
			shn = idx;
			if (c64) { p64(&w, 40, sh); p16(&w, 58, shsz); p16(&w, 60, shn); p16(&w, 62, shn - 1u); }
			else { p32(&w, 32, sh); p16(&w, 46, shsz); p16(&w, 48, shn); p16(&w, 50, shn - 1u); }
			n = sh + shn * shsz;
#undef SEC
		}
	}
	return n;
}

static int parse(const uint8_t *b, uint32_t n, struct kgenome_elf_info *ei, struct kgenome_obj *o)
{
	memset(ei, 0, sizeof *ei);
	memset(o, 0, sizeof *o);
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), ei, o))
		return 0;
	o->file_header = ei;
	return 1;
}

/* ---- the unwind data -------------------------------------------------------------------------------------------- */

struct fde { uint32_t off, len; };

/* .eh_frame for eh_va: one CIE ("zR", pcrel sdata4) and the FDEs, then the terminator. `pos[i]` is where FDE i begins; *cie the CIE's position. */
static uint32_t eh_make(uint8_t *out, int be, uint64_t eh_va, uint64_t text_va, const struct fde *f, unsigned n, uint32_t *pos)
{
	struct wr w = { out, be };
	uint32_t at = 0, i;

	memset(out, 0, 512);
	p32(&w, 0, 20); p32(&w, 4, 0);                  /* CIE: length, id 0 */
	out[8] = 1; out[9] = 'z'; out[10] = 'R'; out[11] = 0; out[12] = 1; out[13] = 0x78; out[14] = 16; out[15] = 1; out[16] = 0x1b;
	at = 24;
	for (i = 0; i < n; i++) {
		uint32_t fp;

		if (i == 1) {                             /* a second CIE between the FDEs (a copy): a pointer that stops short of it must not be read as it */
			memcpy(out + at, out, 24);
			at += 24;
		}
		fp = at + 8u;                             /* the pc_begin field */
		p32(&w, at, 20);
		p32(&w, at + 4, at + 4u);                 /* back to the CIE at 0 */
		p32(&w, fp, (uint32_t)((text_va + f[i].off) - (eh_va + fp)));
		p32(&w, fp + 4, f[i].len);
		if (pos)
			pos[i] = at;
		at += 24;
	}
	p32(&w, at, 0);
	return at + 4u;
}

/* ---- code fixtures ---------------------------------------------------------------------------------------------- */

/* x86-64, 4 functions of 16-byte slots, padded with int3:
 *   0x00 S  call A; call B; ret                     (11 bytes, 5 of padding)
 *   0x10 A  push rbp; mov rbp,rsp; pop rbp; ret     (6, 10 of padding)
 *   0x20 B  push rbp; mov rbp,rsp; nop; nop; pop rbp; ret   (8, 8 of padding)
 *   0x30 C  as A, called by nobody
 */
static uint32_t x86_text(uint8_t *t)
{
	memset(t, 0xcc, 0x40);
	t[0] = 0xe8; { int32_t d = 0x10 - 5; memcpy(t + 1, &d, 4); }
	t[5] = 0xe8; { int32_t d = 0x20 - 10; memcpy(t + 6, &d, 4); }
	t[10] = 0xc3;
	memcpy(t + 0x10, "\x55\x48\x89\xe5\x5d\xc3", 6);
	memcpy(t + 0x20, "\x55\x48\x89\xe5\x90\x90\x5d\xc3", 8);
	memcpy(t + 0x30, "\x55\x48\x89\xe5\x5d\xc3", 6);
	return 0x40;
}

static const struct fde x86_fdes[4] = { { 0, 11 }, { 0x10, 6 }, { 0x20, 8 }, { 0x30, 6 } };

static const struct kgenome_func *fn_at(const struct kgenome_func_set *s, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < s->n; i++)
		if (s->v[i].off == off)
			return &s->v[i];
	return NULL;
}

static uint8_t B[MAXB], T[0x100], EH[512];

#ifndef FNTAB_OLD_API_ONLY
/* ---- the selector: a table (metadata combination -> case) ----------------------------------------------------------------------- */

static void t_selector(void)
{
	static const struct { struct kgenome_fntab_meta m; unsigned ccase, run, check; } rows[] = {
		/* format  rel sym dyn unw se de pe */
		{ { KGENOME_FMT_ELF, 0, 1, 0, 0, 0, 0, 0 }, KGENOME_FNTAB_C_ELF_SYMTAB, KGENOME_FNTAB_X_SYMTAB, 0 },
		{ { KGENOME_FMT_ELF, 0, 1, 1, 1, 0, 0, 0 }, KGENOME_FNTAB_C_ELF_SYMTAB, KGENOME_FNTAB_X_SYMTAB | KGENOME_FNTAB_X_FDE, KGENOME_FN_S_FDE },
		{ { KGENOME_FMT_ELF, 1, 1, 0, 0, 0, 0, 0 }, KGENOME_FNTAB_C_ELF_SYMTAB, KGENOME_FNTAB_X_SYMTAB, 0 },
		/* a symbol table found empty is the next row */
		/* ELF-NO-REACH, fixed 2026-11-05: every row below that runs WALK now runs REACH beside it (KGENOME_FNTAB_X_PE_REACH), exactly as
		 * the equivalent PE rows do (fntab_pe_select.c) - RED on base (these rows held no REACH bit there). ELF_SYMTAB above is untouched:
		 * it never sets WALK, so REACH would have no trace to read (see fntab_select.c's header comment). */
		{ { KGENOME_FMT_ELF, 0, 1, 1, 1, 1, 0, 0 }, KGENOME_FNTAB_C_ELF_DYNSYM, KGENOME_FNTAB_X_DYNSYM | KGENOME_FNTAB_X_FDE | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH, 0 },
		{ { KGENOME_FMT_ELF, 0, 0, 1, 0, 0, 0, 0 }, KGENOME_FNTAB_C_ELF_DYNSYM, KGENOME_FNTAB_X_DYNSYM | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH, 0 },
		{ { KGENOME_FMT_ELF, 0, 0, 1, 1, 0, 1, 0 }, KGENOME_FNTAB_C_ELF_FDE, KGENOME_FNTAB_X_FDE | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH, 0 },
		{ { KGENOME_FMT_ELF, 0, 0, 0, 1, 0, 0, 0 }, KGENOME_FNTAB_C_ELF_FDE, KGENOME_FNTAB_X_FDE | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH, 0 },
		{ { KGENOME_FMT_ELF, 0, 0, 0, 0, 0, 0, 0 }, KGENOME_FNTAB_C_ELF_WALK, KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH, 0 },
		{ { KGENOME_FMT_ELF, 0, 1, 0, 0, 1, 0, 0 }, KGENOME_FNTAB_C_ELF_WALK, KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH, 0 },
		{ { KGENOME_FMT_ELF, 1, 0, 0, 1, 0, 0, 0 }, KGENOME_FNTAB_C_ELF_WALK, 0, 0 },
		/* (the PE rows are tested in fntab_pe.c; this one is the placeholder row of phase A1, now answered by the PE_PDATA row's whole run set) */
		{ { KGENOME_FMT_PE, 0, 0, 0, 0, 0, 0, 1 }, KGENOME_FNTAB_C_PE_PDATA, KGENOME_FNTAB_X_PDATA | KGENOME_FNTAB_X_PE_EXPORT | KGENOME_FNTAB_X_PE_TLS | KGENOME_FNTAB_X_PE_CFG | KGENOME_FNTAB_X_WALK |
		  KGENOME_FNTAB_X_PE_THUNK | KGENOME_FNTAB_X_PE_REACH, 0 },
		{ { KGENOME_FMT_PE, 0, 0, 0, 0, 0, 0, 0 }, KGENOME_FNTAB_C_PE_NONE, 0, 0 },
		{ { 0, 0, 1, 1, 1, 0, 0, 0 }, KGENOME_FNTAB_C_NONE, 0, 0 },
	};
	unsigned i;
	struct kgenome_fntab_plan p;

	for (i = 0; i < sizeof rows / sizeof *rows; i++) {
		p = kgenome_fntab_select(&rows[i].m);
		if (p.ccase != rows[i].ccase || p.run != rows[i].run || p.check_only != rows[i].check)
			printf("  selector row %u: case %u run 0x%x check 0x%x\n", i, p.ccase, p.run, p.check_only);
		CK(p.ccase == rows[i].ccase && p.run == rows[i].run && p.check_only == rows[i].check);
	}
	p = kgenome_fntab_select(NULL);
	CK(p.ccase == KGENOME_FNTAB_C_NONE && !p.run);
}
#endif

/* ---- the symbol-table case ---------------------------------------------------------------------------------------------------- */

/* RED on base: IFUNC, NOTYPE with a size and size-0 symbols are dropped (CN-3). */
static void t_symtab_kinds(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint32_t n;
	const uint64_t va = 0x400000u + TEXT_OFF;
	struct sym s[5] = {
		{ "_start", va, 11, 0x12, 1 },                  /* FUNC */
		{ "resolver", va + 0x10, 6, 0x1a, 1 },          /* GNU_IFUNC */
		{ "asm_lbl", va + 0x20, 8, 0x10, 1 },           /* NOTYPE with a size */
		{ "place", va + 0x30, 0, 0x12, 1 },             /* FUNC of size 0: names a place */
		{ "data_sym", 0x400000u + 0x1000u, 4, 0x11, 1 } /* OBJECT: not a function */
	};

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = T; in.text_n = x86_text(T);
	in.sections = 1; in.sym = s; in.nsym = 5;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_funcs_build(KGENOME_FMT_ELF, B, n, &ei, &fs);
	CK(fs.status == KGENOME_OK && fs.n == 4);
	CK(fn_at(&fs, TEXT_OFF) && fn_at(&fs, TEXT_OFF)->len == 11);
	CK(fn_at(&fs, TEXT_OFF + 0x10) && fn_at(&fs, TEXT_OFF + 0x10)->len == 6);          /* the IFUNC resolver */
	CK(fn_at(&fs, TEXT_OFF + 0x20) && fn_at(&fs, TEXT_OFF + 0x20)->len == 8);          /* the NOTYPE label with .size */
	{
		const struct kgenome_func *z = fn_at(&fs, TEXT_OFF + 0x30);

		/* a size-0 symbol runs to the end of its section (no symbol above it) and says so */
		CK(z && z->len == 0x10);
#ifndef FNTAB_OLD_API_ONLY
		CK(z && (z->flags & KGENOME_FN_F_SIZE0) && (z->flags & KGENOME_FN_F_END_OPEN));
		CK(z && z->end_source == KGENOME_FN_E_NEXT_START);
		CK(fn_at(&fs, TEXT_OFF + 0x10)->kind == KGENOME_FN_IFUNC);
		CK(fn_at(&fs, TEXT_OFF)->end_source == KGENOME_FN_E_SYMBOL && (fn_at(&fs, TEXT_OFF)->source & KGENOME_FN_S_SYMTAB));
#endif
	}
	kgenome_funcs_free(&fs);
	/* a size-0 symbol with a symbol above it ends there */
	s[3].value = va + 0x08; s[3].name = "mid";
	s[2].value = va + 0x20;
	s[0].size = 0;                                  /* _start itself has no size: it runs to the next symbol, "mid" */
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_funcs_build(KGENOME_FMT_ELF, B, n, &ei, &fs);
	CK(fn_at(&fs, TEXT_OFF) && fn_at(&fs, TEXT_OFF)->len == 8);
	kgenome_funcs_free(&fs);
}

/* RED on base: an ARM Thumb function symbol has bit 0 set and its address is the even one (CN-2). */
static void t_symtab_thumb(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint32_t n;
	uint8_t t[0x20];
	const uint64_t va = 0x10000u + TEXT_OFF;
	struct sym s[2] = { { "arm_fn", va, 8, 0x12, 1 }, { "thumb_fn", (va + 8u) | 1u, 8, 0x12, 1 } };

	memset(t, 0, sizeof t);
	memset(&in, 0, sizeof in);
	in.em = 40; in.base = 0x10000u; in.text = t; in.text_n = 0x20; in.sections = 1; in.sym = s; in.nsym = 2;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_funcs_build(KGENOME_FMT_ELF, B, n, &ei, &fs);
	CK(fs.n == 2);
	CK(fn_at(&fs, TEXT_OFF + 8u) != NULL && fn_at(&fs, TEXT_OFF + 9u) == NULL);
	CK(fn_at(&fs, TEXT_OFF + 8u) && fn_at(&fs, TEXT_OFF + 8u)->len == 8);
#ifndef FNTAB_OLD_API_ONLY
	CK(fn_at(&fs, TEXT_OFF + 8u) && fn_at(&fs, TEXT_OFF + 8u)->isa_mode == KGENOME_FN_ISA_THUMB);
	CK(fn_at(&fs, TEXT_OFF) && fn_at(&fs, TEXT_OFF)->isa_mode == KGENOME_FN_ISA_DEFAULT);
#endif
	kgenome_funcs_free(&fs);
}

/* ---- the unwind case --------------------------------------------------------------------------------------------------------- */

static uint32_t build_x86(struct elf_in *in, int sections, int eh_hdr, const struct fde *f, unsigned nf, uint32_t *pos)
{
	struct lay l;

	memset(in, 0, sizeof *in);
	in->c64 = 1; in->em = 62; in->base = 0x400000u; in->text = T; in->text_n = x86_text(T);
	in->rodata_n = 0x40; in->sections = sections; in->eh_hdr = eh_hdr; in->eh_section = sections;
	layout(in, &l);
	in->eh_n = eh_make(EH, 0, l.eh_va, l.text_va, f, nf, pos);
	in->eh = EH;
	return elf_build(in, B);
}

/* RED on base: a stripped file's functions are the call targets only, so C (called by nobody) is missing; its end is the next entry. Here, the unwind table gives
 * start AND length of all four, exact, with the sections present. */
static void t_fde_sections(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint32_t n = build_x86(&in, 1, 0, x86_fdes, 4, NULL);

	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	CK(fs.status == KGENOME_OK && fs.n == 4);
	CK(fn_at(&fs, TEXT_OFF) && fn_at(&fs, TEXT_OFF)->len == 11);
	CK(fn_at(&fs, TEXT_OFF + 0x10) && fn_at(&fs, TEXT_OFF + 0x10)->len == 6);
	CK(fn_at(&fs, TEXT_OFF + 0x20) && fn_at(&fs, TEXT_OFF + 0x20)->len == 8);
	CK(fn_at(&fs, TEXT_OFF + 0x30) && fn_at(&fs, TEXT_OFF + 0x30)->len == 6);           /* the one nobody calls */
#ifndef FNTAB_OLD_API_ONLY
	CK(fs.ccase == KGENOME_FNTAB_C_ELF_FDE);
	CK(fn_at(&fs, TEXT_OFF + 0x30) && fn_at(&fs, TEXT_OFF + 0x30)->end_source == KGENOME_FN_E_UNWIND);
	CK(fn_at(&fs, TEXT_OFF + 0x30) && (fn_at(&fs, TEXT_OFF + 0x30)->source & KGENOME_FN_S_FDE));
	CK(fn_at(&fs, TEXT_OFF + 0x10) && (fn_at(&fs, TEXT_OFF + 0x10)->source == (KGENOME_FN_S_FDE | KGENOME_FN_S_WALK)));   /* two sources agree */
	CK(fs.state == KGENOME_FNTAB_PARTIAL && (fs.partial & KGENOME_FNTAB_P_STARTS));    /* the walk ran: starts a function nobody calls and no FDE names are missing */
	CK(fs.n_disagree == 0);
#endif
	kgenome_funcs_free(&fs);
}

/* The same file with NO section table: the unwind data is found through PT_GNU_EH_FRAME. */
static void t_fde_no_sections(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint32_t n = build_x86(&in, 0, 1, x86_fdes, 4, NULL);

	CK(parse(B, n, &ei, &o));
	CK(ei.sec_count == 0);
	kgenome_diag_funcs_of(&o, B, n, &fs);
	CK(fs.n == 4);
	CK(fn_at(&fs, TEXT_OFF + 0x30) && fn_at(&fs, TEXT_OFF + 0x30)->len == 6);
	CK(fn_at(&fs, TEXT_OFF + 0x20) && fn_at(&fs, TEXT_OFF + 0x20)->len == 8);
	kgenome_funcs_free(&fs);
}

#ifndef FNTAB_OLD_API_ONLY
static unsigned fde_run(const uint8_t *file, uint32_t n, uint32_t *nbad, uint16_t *partial, struct kgenome_func *first)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	unsigned k;

	CK(parse(file, n, &ei, &o));
	memset(&l, 0, sizeof l);
	kgenome_fntab_fde(kof_buf_make(file, n), &ei, &l);
	for (k = 0; k < l.n; k++) {
		/* every entry the strategy keeps lies inside the file and inside the code */
		CK(l.v[k].off >= TEXT_OFF && l.v[k].off + l.v[k].len <= n);
		CK(l.v[k].end_source == KGENOME_FN_E_UNWIND && l.v[k].source == KGENOME_FN_S_FDE);
	}
	if (nbad)
		*nbad = l.n_bad;
	if (partial)
		*partial = l.partial;
	if (first && l.n)
		*first = l.v[0];
	k = l.n;
	kgenome_fntab_list_free(&l);
	return k;
}

/* HOSTILE unwind data: each row poisons one field of a valid table; the strategy keeps what validates, counts what it refuses (P_BAD_FDE), reads nothing out of range. */
static void t_fde_hostile(void)
{
	struct elf_in in;
	uint32_t pos[4], n, nbad, cie_pos = 0, eo, i;
	uint16_t partial;
	struct lay l;
	struct wr w;
	uint8_t sav[512];


	n = build_x86(&in, 1, 0, x86_fdes, 4, pos);
	layout(&in, &l);
	eo = l.eh_off;
	w.b = B; w.be = 0;
	CK(fde_run(B, n, &nbad, &partial, NULL) == 4 && nbad == 0 && partial == 0);
	memcpy(sav, B + eo, 150);

	/* the length of FDE 2 runs past the section: the table ends there (2 kept), the refusal is counted */
	p32(&w, eo + pos[2], 0x7fffff00u);
	CK(fde_run(B, n, &nbad, &partial, NULL) == 2 && nbad >= 1 && (partial & KGENOME_FNTAB_P_BAD_FDE));
	memcpy(B + eo, sav, 150);
	/* a 64-bit length that cannot fit */
	p32(&w, eo + pos[1], 0xffffffffu);
	CK(fde_run(B, n, &nbad, &partial, NULL) <= 1 && nbad >= 1);
	memcpy(B + eo, sav, 150);
	/* the CIE pointer of FDE 1 is past the start of the table */
	p32(&w, eo + pos[1] + 4, 0x10000u);
	CK(fde_run(B, n, &nbad, NULL, NULL) == 3 && nbad == 1);
	memcpy(B + eo, sav, 150);
	/* the CIE pointer names an FDE (not a CIE): refused */
	p32(&w, eo + pos[2] + 4, pos[2] + 4u - pos[1]);
	CK(fde_run(B, n, &nbad, NULL, NULL) == 3 && nbad == 1);
	memcpy(B + eo, sav, 150);
	/* the CIE pointer lands inside a record, not on its start (a CIE follows: the nearest one above is not it) */
	p32(&w, eo + pos[2] + 4, pos[2] + 4u - 1u);
	CK(fde_run(B, n, &nbad, NULL, NULL) == 3 && nbad == 1);
	memcpy(B + eo, sav, 150);
	/* pc_range 0 */
	p32(&w, eo + pos[1] + 12, 0);
	CK(fde_run(B, n, &nbad, NULL, NULL) == 3 && nbad == 1);
	memcpy(B + eo, sav, 150);
	/* the range runs out of the segment */
	p32(&w, eo + pos[3] + 12, 0x10000000u);
	CK(fde_run(B, n, &nbad, NULL, NULL) == 3 && nbad == 1);
	memcpy(B + eo, sav, 150);
	/* the start is before the segment's code (below the load address) */
	p32(&w, eo + pos[0] + 8, 0xf0000000u);
	CK(fde_run(B, n, &nbad, NULL, NULL) == 3 && nbad == 1);
	memcpy(B + eo, sav, 150);
	/* two ranges overlap: the first stands, the second is counted */
	p32(&w, eo + pos[2] + 12, 0x28u);
	CK(fde_run(B, n, &nbad, NULL, NULL) == 3 && nbad == 1);      /* B now spans C's start: C begins inside B and is refused */
	memcpy(B + eo, sav, 150);
	/* an encoding this does not read (datarel in the CIE): every FDE of it is refused, none misread */
	B[eo + 16] = 0x3b;
	CK(fde_run(B, n, &nbad, NULL, NULL) == 0 && nbad == 4);
	memcpy(B + eo, sav, 150);
	/* a CIE of an unknown version: its FDEs are refused */
	B[eo + 8] = 9;
	CK(fde_run(B, n, &nbad, NULL, NULL) == 0 && nbad == 4);
	memcpy(B + eo, sav, 150);
	/* the CIE record is cut short by its own length */
	p32(&w, eo, 5);
	{
		unsigned k = fde_run(B, n, &nbad, NULL, NULL);
		CK(k <= 4);
	}
	memcpy(B + eo, sav, 150);
	cie_pos = 0;
	(void)cie_pos;
	/* every prefix of the file (the section is cut anywhere) and every single-byte poison of the table: no crash, entries stay inside */
	for (i = 0; i < 150; i++) {
		uint8_t keep = B[eo + i];

		B[eo + i] ^= 0xffu;
		(void)fde_run(B, n, NULL, NULL, NULL);
		B[eo + i] = (uint8_t)(keep ^ 0x80u);
		(void)fde_run(B, n, NULL, NULL, NULL);
		B[eo + i] = keep;
	}
	for (i = 0; i < 8; i++)
		(void)fde_run(B, eo + 4u * i, NULL, NULL, NULL);
}
#endif

/* ---- disagreement: a symbol and an FDE give one start with two ends ---------------------------------------------------------- */

static void t_symtab_fde_disagree(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	const uint64_t va = 0x400000u + TEXT_OFF;
	/* the symbols name S (11), A with size 20 (the FDE says 6), B (8); C is not named */
	struct sym s[3] = { { "s", va, 11, 0x12, 1 }, { "a", va + 0x10, 20, 0x12, 1 }, { "b", va + 0x20, 8, 0x12, 1 } };
	uint32_t n = build_x86(&in, 1, 0, x86_fdes, 4, NULL);

	in.sym = s; in.nsym = 3;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	/* the symbol table stands (exact path unchanged: 3 functions, A with the symbol's size) */
	CK(fs.n == 3);
	CK(fn_at(&fs, TEXT_OFF + 0x10) && fn_at(&fs, TEXT_OFF + 0x10)->len == 20);
	CK(fn_at(&fs, TEXT_OFF + 0x30) == NULL);        /* the FDE of C is a check only: it does not enter a symbol-table object */
#ifndef FNTAB_OLD_API_ONLY
	CK(fs.ccase == KGENOME_FNTAB_C_ELF_SYMTAB);
	CK(fs.n_disagree == 1);
	CK(fn_at(&fs, TEXT_OFF + 0x10) && (fn_at(&fs, TEXT_OFF + 0x10)->flags & KGENOME_FN_F_DISAGREE));
	CK(fn_at(&fs, TEXT_OFF + 0x10) && (fn_at(&fs, TEXT_OFF + 0x10)->source == (KGENOME_FN_S_SYMTAB | KGENOME_FN_S_FDE)));
	/* and the table says that the symbols lack a function the unwind data names */
	CK(fs.state == KGENOME_FNTAB_PARTIAL && (fs.partial & KGENOME_FNTAB_P_SYMTAB));
	CK(fs.n_extra >= 1);
#endif
	kgenome_funcs_free(&fs);
	/* with the symbol of C present the symbols are complete: COMPLETE, no disagreement */
	{
		struct sym s2[4] = { { "s", va, 11, 0x12, 1 }, { "a", va + 0x10, 6, 0x12, 1 }, { "b", va + 0x20, 8, 0x12, 1 }, { "c", va + 0x30, 6, 0x12, 1 } };

		in.sym = s2; in.nsym = 4;
		n = elf_build(&in, B);
		CK(parse(B, n, &ei, &o));
		kgenome_diag_funcs_of(&o, B, n, &fs);
		CK(fs.n == 4);
#ifndef FNTAB_OLD_API_ONLY
		CK(fs.state == KGENOME_FNTAB_COMPLETE && fs.partial == 0 && fs.n_disagree == 0);
#endif
		kgenome_funcs_free(&fs);
	}
}

/* ---- the walk case: stripped, no unwind data -------------------------------------------------------------------------------------- */

/*
 * ELF-NO-REACH, fixed 2026-11-05 (RED on base, GREEN on tree): before the fix, a function ran to the next entry
 * INCLUDING the alignment padding in front of it, and the last function ran to the segment's end (into .rodata) -
 * C ("called by nobody") was swallowed into B's body with no evidence it was ever examined. With REACH now running
 * for ELF_WALK (fntab_select.c), each entry's own end is the end of what it reaches (S and A unchanged; B now ends
 * at its own `pop rbp; ret`, 8 bytes, not 0x16), and the gap behind B is walked: C's own bytes decode and end (a
 * `ret`), so C is recovered as its own entry, flag GAP, end_source REACH - exactly the mechanism PE's
 * fnr4_reach_stops_at_padding already had (see fntab_pe.c), now also on ELF. Measured (this run's own output, not
 * guessed): fs.n 3->4, B->len 0x16->8, every end_source NEXT_START/TRIMMED->REACH, KGENOME_FNTAB_P_ENDS no longer
 * set (every end is now established, not merely "the next start").
 */
static void t_walk_x86(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint32_t n = build_x86(&in, 1, 0, NULL, 0, NULL);       /* sections, no unwind data */

	in.eh_n = 0;
	in.eh = NULL;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	/* entries: S (the entry point), A, B (call targets), and now C too - its own bytes decode and end, so REACH's
	 * gap step finds it behind B even though nothing calls it (the call-target walk alone never would). */
	CK(fs.n == 4);
	CK(fn_at(&fs, TEXT_OFF) && fn_at(&fs, TEXT_OFF)->len == 11);            /* the int3 padding is not the function */
	CK(fn_at(&fs, TEXT_OFF + 0x10) && fn_at(&fs, TEXT_OFF + 0x10)->len == 6);
	/* B now ends at its own ret (8 bytes), not at 0x16 swallowing C's bytes with it */
	CK(fn_at(&fs, TEXT_OFF + 0x20) && fn_at(&fs, TEXT_OFF + 0x20)->len == 8);
	CK(fn_at(&fs, TEXT_OFF + 0x30) && fn_at(&fs, TEXT_OFF + 0x30)->len == 6);          /* C, recovered */
#ifndef FNTAB_OLD_API_ONLY
	CK(fs.ccase == KGENOME_FNTAB_C_ELF_WALK);
	/* every end is now REACH, established: P_ENDS (some end is merely "the next start") no longer applies */
	CK(fs.state == KGENOME_FNTAB_PARTIAL && (fs.partial & (KGENOME_FNTAB_P_STARTS | KGENOME_FNTAB_P_ENDS)) == KGENOME_FNTAB_P_STARTS);
	CK(fn_at(&fs, TEXT_OFF)->end_source == KGENOME_FN_E_REACH);
	CK(!(fn_at(&fs, TEXT_OFF)->flags & KGENOME_FN_F_END_OPEN));
	CK((fn_at(&fs, TEXT_OFF)->source & (KGENOME_FN_S_WALK | KGENOME_FN_S_ENTRY)) == KGENOME_FN_S_ENTRY);
	CK(fn_at(&fs, TEXT_OFF + 0x30) && fn_at(&fs, TEXT_OFF + 0x30)->source == KGENOME_FN_S_WALK && (fn_at(&fs, TEXT_OFF + 0x30)->flags & KGENOME_FN_F_GAP));
	CK(fn_at(&fs, TEXT_OFF + 0x30) && fn_at(&fs, TEXT_OFF + 0x30)->end_source == KGENOME_FN_E_REACH);
#endif
	kgenome_funcs_free(&fs);

	/* the same without a section table: the segment is the only statement of the code (the extent keeps its end);
	 * C is recovered here too - nothing about the gap step needs a section table. */
	{
		struct elf_in in2 = in;
		uint32_t n2;

		in2.sections = 0;
		n2 = elf_build(&in2, B);
		CK(parse(B, n2, &ei, &o));
		kgenome_diag_funcs_of(&o, B, n2, &fs);
		CK(fs.n == 4 && fn_at(&fs, TEXT_OFF + 0x10) && fn_at(&fs, TEXT_OFF + 0x10)->len == 6);
		kgenome_funcs_free(&fs);
	}
	/* the entry point beyond the last executable section (a table that hides code): the segment's end stands */
	{
		struct elf_in in3 = in;
		uint32_t n3;
		struct wr w = { B, 0 };

		n3 = elf_build(&in3, B);
		p64(&w, 24, 0x400000u + 0x150u);                       /* the entry: inside .rodata's bytes */
		CK(parse(B, n3, &ei, &o));
		{
			uint64_t at = 0, have = kgenome_diag_extent(&o, 0, n3, &at);
			CK(have && at + have == in3.rodata_n + al(TEXT_OFF + in3.text_n, 4u));     /* the segment end (no eh_frame here) */
		}
	}
	/* the extent ends with .text when the table is honest */
	{
		uint64_t at = 0, have;

		n = elf_build(&in, B);
		CK(parse(B, n, &ei, &o));
		have = kgenome_diag_extent(&o, 0, n, &at);
		CK(have && at == TEXT_OFF && at + have == TEXT_OFF + in.text_n);
	}
}

/*
 * Originally RED on base (the function table did not exist): the owner's Q1 - does a test pin the accuracy GAP
 * between the FDE-present case (t_fde_sections: 4/4 exact) and the walk-only case with NO symtab, NO dynsym and NO
 * .eh_frame at all? This is the extreme of that gap: zero call edges anywhere, so the call-target walk's only
 * evidence is the entry point (fntab_walk.c) - on base this collapsed recall to ONE function regardless of how many
 * real functions the text held.
 *
 * ELF-NO-REACH, fixed 2026-11-05 (RED on the base above this comment, GREEN on tree): REACH does not need a call
 * edge at all - it reads what is LEFT in the gap behind an entry's own end and asks only "does this decode as code
 * that ends", which A/B/C's identical push/mov/pop/ret shape answers yes to. So the walk-only, zero-call-edge case
 * is no longer the MECHANISM's worst case the way this comment used to say: all of A, B and C are now recovered, as
 * GAP entries (KGENOME_FN_F_GAP, source WALK, end_source REACH), with no call to any of them ever found. This is
 * independent of fntab.h's still-open "reachable-blocks END rule" (R1): R1 is about which STARTS are found from a
 * function nothing calls directly reached through another's own graph; REACH's gap step is a separate, now-enabled
 * mechanism that finds a start from what is left over after the known entries, not from anyone reaching it.
 */
static void t_walk_no_calls_collapse(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint8_t t[0x40];
	uint32_t n;

	memset(t, 0xcc, sizeof t);                                       /* the tail past the last real byte: trimmed as padding */
	t[0] = 0xc3;                                                     /* S: ret (1 byte); nothing calls A, B or C */
	memcpy(t + 1, "\x55\x48\x89\xe5\x5d\xc3", 6);                    /* A: push rbp; mov rbp,rsp; pop rbp; ret */
	memcpy(t + 7, "\x55\x48\x89\xe5\x5d\xc3", 6);                    /* B: same shape, reachable only by falling through S's body */
	memcpy(t + 13, "\x55\x48\x89\xe5\x5d\xc3", 6);                   /* C: same shape */

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = t; in.text_n = sizeof t; in.rodata_n = 0x20; in.sections = 1;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	CK(fs.n == 4);
#ifndef FNTAB_OLD_API_ONLY
	CK(fs.ccase == KGENOME_FNTAB_C_ELF_WALK);
	CK(fs.state == KGENOME_FNTAB_PARTIAL && (fs.partial & KGENOME_FNTAB_P_STARTS));
#endif
	CK(fn_at(&fs, TEXT_OFF) != NULL && fn_at(&fs, TEXT_OFF)->len == 1);
	CK(fn_at(&fs, TEXT_OFF + 1u) && fn_at(&fs, TEXT_OFF + 1u)->len == 6);     /* A: recovered by REACH's gap step */
	CK(fn_at(&fs, TEXT_OFF + 7u) && fn_at(&fs, TEXT_OFF + 7u)->len == 6);     /* B: recovered */
	CK(fn_at(&fs, TEXT_OFF + 13u) && fn_at(&fs, TEXT_OFF + 13u)->len == 6);   /* C: recovered */
#ifndef FNTAB_OLD_API_ONLY
	CK(fn_at(&fs, TEXT_OFF + 1u) && fn_at(&fs, TEXT_OFF + 1u)->source == KGENOME_FN_S_WALK && (fn_at(&fs, TEXT_OFF + 1u)->flags & KGENOME_FN_F_GAP));
	CK(fn_at(&fs, TEXT_OFF + 1u) && fn_at(&fs, TEXT_OFF + 1u)->end_source == KGENOME_FN_E_REACH);
#endif
	kgenome_funcs_free(&fs);

	/* the same shape with the FDE strategy fed (round trip of the gap): giving the unwind table back the 4 starts
	 * restores exact recall, on the identical bytes - the only variable is which evidence the case has. */
	{
		struct elf_in in2;
		struct kgenome_elf_info ei2;
		struct kgenome_obj o2;
		struct kgenome_func_set fs2;
		struct lay l2;
		static const struct fde leaf_fdes[4] = { { 0, 1 }, { 1, 6 }, { 7, 6 }, { 13, 6 } };
		uint32_t n2;

		memset(&in2, 0, sizeof in2);
		in2.c64 = 1; in2.em = 62; in2.base = 0x400000u; in2.text = t; in2.text_n = sizeof t;
		in2.rodata_n = 0x20; in2.sections = 1; in2.eh_section = 1;
		layout(&in2, &l2);
		in2.eh_n = eh_make(EH, 0, l2.eh_va, l2.text_va, leaf_fdes, 4, NULL);
		in2.eh = EH;
		n2 = elf_build(&in2, B);
		CK(parse(B, n2, &ei2, &o2));
		kgenome_diag_funcs_of(&o2, B, n2, &fs2);
		CK(fs2.n == 4);
		CK(fn_at(&fs2, TEXT_OFF + 1u) && fn_at(&fs2, TEXT_OFF + 1u)->len == 6);
		CK(fn_at(&fs2, TEXT_OFF + 7u) && fn_at(&fs2, TEXT_OFF + 7u)->len == 6);
		CK(fn_at(&fs2, TEXT_OFF + 13u) && fn_at(&fs2, TEXT_OFF + 13u)->len == 6);
		kgenome_funcs_free(&fs2);
	}
}

/*
 * ELF-NO-REACH, fixed 2026-11-05 (RED on base, GREEN on tree): the ELF twin of fntab_pe.c's fnr4_reach_stops_at_padding
 * (case 1 there). f is the object's entry point and has NO terminator of its own (just one `push ebp`): on base,
 * fntab_ends.c's trim finds g's own two real bytes in the middle of the long 0xcc run and so trims only back to the
 * byte after g, leaving f's end at g's own end - f swallows g whole (RED). With REACH, f's own graph (graph_of) walks
 * one reachable block from its entry; crosses_pad (fntab_reach.c) stops that walk at the FIRST byte of the genuine,
 * multi-byte int3 run that follows f's single instruction - f cannot run through the padding into g by construction,
 * REACH closing it at len 1 (R_OK, cut_by_pad) - and the gap step then finds g on its own, behind the padding.
 */
static void t_walk_padding_crossing(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint8_t t[0x20];
	uint32_t n;

	memset(t, 0xcc, sizeof t);
	t[0] = 0x55;                              /* f: push ebp - no ret: nothing of its own ends the block before the padding */
	memcpy(t + 0x10, "\x55\xc3", 2);           /* g: push ebp; ret - a real second function behind 15 bytes of alignment padding, no call anywhere near it */

	memset(&in, 0, sizeof in);
	in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = t; in.text_n = sizeof t; in.rodata_n = 0x20; in.sections = 1;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	CK(fs.n == 2);
	CK(fn_at(&fs, TEXT_OFF) && fn_at(&fs, TEXT_OFF)->len == 1);                      /* f's own push, not the 15 bytes of padding plus g */
	CK(fn_at(&fs, TEXT_OFF + 0x10) && fn_at(&fs, TEXT_OFF + 0x10)->len == 2);        /* g, found behind the padding f no longer swallows */
#ifndef FNTAB_OLD_API_ONLY
	CK(fn_at(&fs, TEXT_OFF)->end_source == KGENOME_FN_E_REACH);
	CK(fn_at(&fs, TEXT_OFF + 0x10) && fn_at(&fs, TEXT_OFF + 0x10)->source == KGENOME_FN_S_WALK && (fn_at(&fs, TEXT_OFF + 0x10)->flags & KGENOME_FN_F_GAP));
#endif
	kgenome_funcs_free(&fs);

	/* Non-regression (the same FNR-1/FNR-4 fallthrough fntab_pe.c's own case 2 pins): a single int3 NOT part of any
	 * recorded padding run - real instructions on both sides - must still fall through as ordinary flow. f here has
	 * no terminator until its own final ret, so the whole 7-byte chunk is one reachable block. */
	memset(t, 0xcc, sizeof t);
	memcpy(t, "\x55\x31\xc0\xcc\x31\xc9\xc3", 7);   /* f: push ebp; xor eax,eax; int3; xor ecx,ecx; ret - no terminator before the lone int3 */
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	CK(fn_at(&fs, TEXT_OFF) && fn_at(&fs, TEXT_OFF)->len == 7);      /* the whole chunk, including past the lone int3: not a recorded run, does not stop the walk */
#ifndef FNTAB_OLD_API_ONLY
	CK(fn_at(&fs, TEXT_OFF)->end_source == KGENOME_FN_E_REACH);
#endif
	kgenome_funcs_free(&fs);
}

/* one table of the call-target walk on an architecture: S calls A and B; each body is followed by `pad` words of padding. `word` writes one instruction. */
struct arch_fx {
	const char *name;
	int c64, be;
	uint16_t em;
	uint64_t base;
	uint32_t nops;                  /* padding words after S, A and B */
	uint32_t a_len, b_len, s_len;   /* the expected length of each function, padding cut off (a delay slot is kept) */
	uint32_t pad_word;              /* ARM: the padding word (0xe1a00000 mov r0,r0, or 0: the linker's fill) */
};

static void w32(uint8_t *p, int be, uint32_t v) { struct wr w = { p, be }; p32(&w, 0, v); }

static void t_walk_arch(const struct arch_fx *fx)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint8_t t[0x80];
	uint32_t n, i, s_off = 0, a_off, b_off, p = 0;
	uint32_t va0 = (uint32_t)fx->base + TEXT_OFF;

	memset(t, 0, sizeof t);
	/* layout in words; A and B first fixed so S can call them */
	if (fx->em == 40) {                     /* ARM: bl A; bl B; bx lr; nop... */
		s_off = 0; a_off = 0x20; b_off = 0x30;
		for (i = 0; i < 4; i++) {
			uint32_t tgt = i == 0 ? a_off : b_off;
			if (i < 2) { w32(t + 4 * i, fx->be, 0xeb000000u | (((tgt - (4u * i + 8u)) >> 2) & 0xffffffu)); }
		}
		w32(t + 8, fx->be, 0xe12fff1eu);                                     /* bx lr */
		for (i = 3; i < 8; i++) w32(t + 4 * i, fx->be, fx->pad_word);      /* the padding */
		w32(t + a_off, fx->be, 0xe3a00001u); w32(t + a_off + 4, fx->be, 0xe12fff1eu);
		for (i = 2; i < 4; i++) w32(t + a_off + 4 * i, fx->be, fx->pad_word);
		w32(t + b_off, fx->be, 0xe3a00002u); w32(t + b_off + 4, fx->be, 0xe3a01003u); w32(t + b_off + 8, fx->be, 0xe12fff1eu);
		for (i = 3; i < 4; i++) w32(t + b_off + 4 * i, fx->be, fx->pad_word);
	} else if (fx->em == 8) {               /* MIPS: jal A; nop; jal B; nop; jr ra; nop(delay) then nops */
		s_off = 0; a_off = 0x20; b_off = 0x30;
		w32(t + 0, fx->be, 0x0c000000u | (((va0 + a_off) & 0x0fffffffu) >> 2)); w32(t + 4, fx->be, 0);
		w32(t + 8, fx->be, 0x0c000000u | (((va0 + b_off) & 0x0fffffffu) >> 2)); w32(t + 12, fx->be, 0);
		w32(t + 16, fx->be, 0x03e00008u); w32(t + 20, fx->be, 0);          /* jr ra ; delay slot */
		w32(t + 24, fx->be, 0); w32(t + 28, fx->be, 0);                       /* padding */
		w32(t + a_off, fx->be, 0x24020001u); w32(t + a_off + 4, fx->be, 0x03e00008u); w32(t + a_off + 8, fx->be, 0);   /* addiu; jr ra; delay */
		w32(t + a_off + 12, fx->be, 0);                                       /* padding */
		w32(t + b_off, fx->be, 0x24020002u); w32(t + b_off + 4, fx->be, 0x24030003u); w32(t + b_off + 8, fx->be, 0x03e00008u); w32(t + b_off + 12, fx->be, 0);
		/* B's delay slot is its last word: nothing after it but the end of .text */
	} else {                                /* PowerPC: bl A; bl B; blr; nop... */
		s_off = 0; a_off = 0x20; b_off = 0x30;
		w32(t + 0, fx->be, 0x48000001u | ((a_off - 0u) & 0x03fffffcu));
		w32(t + 4, fx->be, 0x48000001u | ((b_off - 4u) & 0x03fffffcu));
		w32(t + 8, fx->be, 0x4e800020u);
		for (i = 3; i < 8; i++) w32(t + 4 * i, fx->be, 0x60000000u);
		w32(t + a_off, fx->be, 0x38600001u); w32(t + a_off + 4, fx->be, 0x4e800020u);
		for (i = 2; i < 4; i++) w32(t + a_off + 4 * i, fx->be, 0x60000000u);
		w32(t + b_off, fx->be, 0x38600002u); w32(t + b_off + 4, fx->be, 0x38800003u); w32(t + b_off + 8, fx->be, 0x4e800020u);
		for (i = 3; i < 4; i++) w32(t + b_off + 4 * i, fx->be, 0x60000000u);
	}
	(void)p;
	memset(&in, 0, sizeof in);
	in.c64 = fx->c64; in.be = fx->be; in.em = fx->em; in.base = fx->base; in.text = t; in.text_n = 0x40; in.rodata_n = 0x20; in.sections = 1;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	if (fs.n != 3 || !fn_at(&fs, TEXT_OFF + s_off) || !fn_at(&fs, TEXT_OFF + a_off) || !fn_at(&fs, TEXT_OFF + b_off)) {
		printf("  %s: %u functions\n", fx->name, fs.n);
		for (i = 0; i < fs.n; i++)
			printf("    off %llx len %llu\n", (unsigned long long)fs.v[i].off, (unsigned long long)fs.v[i].len);
	}
	CK(fs.n == 3);
	CK(fn_at(&fs, TEXT_OFF + s_off) && fn_at(&fs, TEXT_OFF + s_off)->len == fx->s_len);
	CK(fn_at(&fs, TEXT_OFF + a_off) && fn_at(&fs, TEXT_OFF + a_off)->len == fx->a_len);
	CK(fn_at(&fs, TEXT_OFF + b_off) && fn_at(&fs, TEXT_OFF + b_off)->len == fx->b_len);
	if (fs.n == 3 && (fn_at(&fs, TEXT_OFF + a_off)->len != fx->a_len || fn_at(&fs, TEXT_OFF + s_off)->len != fx->s_len))
		printf("  %s: S %llu A %llu B %llu\n", fx->name, (unsigned long long)fn_at(&fs, TEXT_OFF + s_off)->len, (unsigned long long)fn_at(&fs, TEXT_OFF + a_off)->len, (unsigned long long)fn_at(&fs, TEXT_OFF + b_off)->len);
	kgenome_funcs_free(&fs);
}

/*
 * Owner's Q2 (D4): t_walk_arch's "mips-be" row above builds S calling A and B with DIRECT `jal`, and asserts the
 * CORRECT result (3 functions) - so that row does NOT pin D4. Direct `jal` already works: pass_a
 * (diag_wrapper_walk.c) pushes the target of any KGENOME_CELL_CALL that is not KGENOME_CELL_F_INDIRECT, and a MIPS
 * `jal`'s target is read straight from the J-type immediate (decode_mips.c, MF_J) like any other architecture's
 * direct call - the walk's call-target logic is generic by instruction class, not "x86 only" as STATUS.md's older
 * D4 note (section "Defects from A1 coverage audit") says; that line is STALE.
 *
 * UPDATED (CN-5's fix, this round): `jalr $t9` is now resolved when it is preceded, straight-line, by
 * `lw $t9, off($gp)` AND the object's own `.got` section lets $gp be fixed (mips_gp_of, mips_got_target in
 * diag_wrapper_walk.c) - see t_walk_mips_indirect_jalr_got below for that, now-green, case. THIS test builds
 * the object with NO `.got` section at all (a sstripped MIPS32 object, or any object that kept no section
 * table): CN-5's call resolution still, correctly, PINS the conservative fallback here - with no `.got` to fix
 * $gp from, every `jalr $t9` is left exactly as before, whatever precedes it, and no new CALL edge to A or B
 * is ever added by pass_a.
 *
 * ELF-NO-REACH, fixed 2026-11-05 (RED on base, GREEN on tree): CN-5's call resolution declining here does NOT
 * mean A and B stay swallowed any more. REACH does not need a call edge: S's own graph now ends at its real
 * `jr ra` (0x18 bytes, not the whole text), the zero fill behind it is recognised padding (any-width NOP, which
 * MIPS's all-zero `sll $zero,$zero,0` word decodes as), and A's and B's own bytes - independently, with no edge
 * from S - decode and end (`jr ra`), so REACH's gap step finds both as GAP entries. This is the SAME mechanism
 * t_walk_no_calls_collapse exercises on x86, now shown on an architecture whose indirect call the walk never
 * resolves at all: the measured result is fs.n 1->3, with A and B recovered purely from the padding-bounded gap,
 * never from the (still unresolved) `jalr $t9`.
 */
static void t_walk_mips_indirect_jalr(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint8_t t[0x40];
	uint32_t n;

	memset(t, 0, sizeof t);
	w32(t + 0x00, 1, 0x0320f809u);     /* S: jalr $t9 (meant to reach A) */
	w32(t + 0x04, 1, 0u);              /* delay slot */
	w32(t + 0x08, 1, 0x0320f809u);     /* S: jalr $t9 (meant to reach B) */
	w32(t + 0x0c, 1, 0u);              /* delay slot */
	w32(t + 0x10, 1, 0x03e00008u);     /* S: jr ra */
	w32(t + 0x14, 1, 0u);              /* delay slot */
	/* [0x18, 0x20): the linker's zero fill (MIPS zeronop) */
	w32(t + 0x20, 1, 0x24020001u);     /* A: addiu v0,0,1 */
	w32(t + 0x24, 1, 0x03e00008u);     /* A: jr ra */
	w32(t + 0x28, 1, 0u);              /* A: delay slot */
	/* [0x2c, 0x30): zero fill */
	w32(t + 0x30, 1, 0x24020002u);     /* B: addiu v0,0,2 */
	w32(t + 0x34, 1, 0x24030003u);     /* B: addiu v1,0,3 */
	w32(t + 0x38, 1, 0x03e00008u);     /* B: jr ra */
	w32(t + 0x3c, 1, 0u);              /* B: delay slot, ends the text exactly */

	memset(&in, 0, sizeof in);
	in.be = 1; in.em = 8; in.base = 0x400000u; in.text = t; in.text_n = sizeof t; in.rodata_n = 0x20; in.sections = 1;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	CK(fs.n == 3);                                    /* S, A and B: REACH's gap step recovers A and B with no call edge to either */
#ifndef FNTAB_OLD_API_ONLY
	CK(fs.ccase == KGENOME_FNTAB_C_ELF_WALK);
#endif
	CK(fn_at(&fs, TEXT_OFF) != NULL);
	CK(fn_at(&fs, TEXT_OFF) && fn_at(&fs, TEXT_OFF)->len == 0x18);        /* S's own body, ending at its real jr ra */
	CK(fn_at(&fs, TEXT_OFF + 0x20) && fn_at(&fs, TEXT_OFF + 0x20)->len == 0xc);     /* A: recovered by REACH's gap step */
	CK(fn_at(&fs, TEXT_OFF + 0x30) && fn_at(&fs, TEXT_OFF + 0x30)->len == 0x10);    /* B: recovered */
#ifndef FNTAB_OLD_API_ONLY
	CK(fn_at(&fs, TEXT_OFF + 0x20) && fn_at(&fs, TEXT_OFF + 0x20)->source == KGENOME_FN_S_WALK && (fn_at(&fs, TEXT_OFF + 0x20)->flags & KGENOME_FN_F_GAP));
	CK(fn_at(&fs, TEXT_OFF)->end_source == KGENOME_FN_E_REACH);
#endif
	kgenome_funcs_free(&fs);
}

/*
 * RED on base, GREEN on tree: CN-5's actual fix. S reaches A and B only through `jalr $t9`, each preceded,
 * straight-line, by the real MIPS o32 PIC shape `lw $t9, off($gp)` - the GOT entries hold A's and B's real
 * addresses (a static linker fills a LOCAL GOT entry outright, no relocation needed), and the object carries
 * a `.got` section so mips_gp_of can fix $gp = .got's address + 0x7ff0 (the SVR4 MIPS ABI convention). On
 * base this is still one unit (pass_a has no indirect-call handling at all); on tree pass_a resolves both
 * calls through mips_got_target and A and B are found as their own entries.
 */
static void t_walk_mips_indirect_jalr_got(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint8_t t[0x48];
	uint8_t got[8];
	uint64_t a_va, b_va;
	uint32_t n;

	memset(t, 0, sizeof t);
	w32(t + 0x00, 1, 0x8f998010u);     /* S: lw $t9, -0x7ff0($gp)  (A's GOT slot) */
	w32(t + 0x04, 1, 0x0320f809u);     /* S: jalr $t9 */
	w32(t + 0x08, 1, 0u);              /* delay slot */
	w32(t + 0x0c, 1, 0x8f998014u);     /* S: lw $t9, -0x7fec($gp) (B's GOT slot) */
	w32(t + 0x10, 1, 0x0320f809u);     /* S: jalr $t9 */
	w32(t + 0x14, 1, 0u);              /* delay slot */
	w32(t + 0x18, 1, 0x03e00008u);     /* S: jr ra */
	w32(t + 0x1c, 1, 0u);              /* delay slot */
	/* [0x20, 0x28): the linker's zero fill (MIPS zeronop) */
	w32(t + 0x28, 1, 0x24020001u);     /* A: addiu v0,0,1 */
	w32(t + 0x2c, 1, 0x03e00008u);     /* A: jr ra */
	w32(t + 0x30, 1, 0u);              /* A: delay slot */
	/* [0x34, 0x38): zero fill */
	w32(t + 0x38, 1, 0x24020002u);     /* B: addiu v0,0,2 */
	w32(t + 0x3c, 1, 0x24030003u);     /* B: addiu v1,0,3 */
	w32(t + 0x40, 1, 0x03e00008u);     /* B: jr ra */
	w32(t + 0x44, 1, 0u);              /* B: delay slot, ends the text exactly */

	memset(&in, 0, sizeof in);
	in.be = 1; in.em = 8; in.base = 0x400000u; in.text = t; in.text_n = sizeof t; in.rodata_n = 0x20; in.sections = 1;
	a_va = in.base + TEXT_OFF + 0x28; b_va = in.base + TEXT_OFF + 0x38;
	memset(got, 0, sizeof got);
	{ struct wr gw = { got, 1 }; p32(&gw, 0, (uint32_t)a_va); p32(&gw, 4, (uint32_t)b_va); }
	in.got = got; in.got_n = sizeof got;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	if (fs.n != 3)
		printf("  mips-got: %u functions (want 3)\n", fs.n);
	CK(fs.n == 3);
	CK(fn_at(&fs, TEXT_OFF) != NULL);
	CK(fn_at(&fs, TEXT_OFF + 0x28) != NULL);          /* A: found as its own entry (CN-5's fix) */
	CK(fn_at(&fs, TEXT_OFF + 0x38) != NULL);          /* B: found as its own entry (CN-5's fix) */
	kgenome_funcs_free(&fs);
}

/*
 * Conservative fallback, explicit: the SAME `.got` section and the SAME GOT values as the test above (so $gp
 * IS known), but $t9 is set by an instruction that is NOT the recognised `lw $t9, off($gp)` shape (here,
 * `move $t9, $v0` - a real indirect call through a value the walk cannot know statically). CN-5's call
 * resolution must not guess: it still adds no edge to A, exactly as before that fix.
 *
 * ELF-NO-REACH, fixed 2026-11-05 (RED on base, GREEN on tree): as in t_walk_mips_indirect_jalr above, REACH
 * recovers A anyway, through the SAME call-edge-free gap mechanism (S's real end at its own `jr ra`, 0x18
 * bytes; the zero-fill gap recognised as padding; A's own bytes decode and end). This is not CN-5's call
 * resolution finding A - that part is still, correctly, conservative - it is the separate reach/gap step.
 */
static void t_walk_mips_indirect_jalr_no_lw(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	uint8_t t[0x30];
	uint8_t got[4];
	uint64_t a_va;
	uint32_t n;

	memset(t, 0, sizeof t);
	w32(t + 0x00, 1, 0x02202021u);     /* S: move $a0,$s1 (an unrelated instruction, holds the slot) */
	w32(t + 0x04, 1, 0x0040c821u);     /* S: move $t9,$v0 (addu $t9,$v0,$zero) - $t9 from a register, not the GOT */
	w32(t + 0x08, 1, 0x0320f809u);     /* S: jalr $t9 */
	w32(t + 0x0c, 1, 0u);              /* delay slot */
	w32(t + 0x10, 1, 0x03e00008u);     /* S: jr ra */
	w32(t + 0x14, 1, 0u);              /* delay slot */
	/* [0x18, 0x20): zero fill */
	w32(t + 0x20, 1, 0x24020001u);     /* A: addiu v0,0,1 */
	w32(t + 0x24, 1, 0x03e00008u);     /* A: jr ra */
	w32(t + 0x28, 1, 0u);              /* A: delay slot, ends the text exactly */

	memset(&in, 0, sizeof in);
	in.be = 1; in.em = 8; in.base = 0x400000u; in.text = t; in.text_n = sizeof t; in.rodata_n = 0x20; in.sections = 1;
	a_va = in.base + TEXT_OFF + 0x20;
	memset(got, 0, sizeof got);
	{ struct wr gw = { got, 1 }; p32(&gw, 0, (uint32_t)a_va); }
	in.got = got; in.got_n = sizeof got;        /* $gp IS known here: the fallback is about the missing lw-pattern, not a missing .got */
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));
	kgenome_diag_funcs_of(&o, B, n, &fs);
	CK(fs.n == 2);                                    /* S and A: REACH's gap step recovers A with no call edge to it, CN-5's resolution still declines */
	CK(fn_at(&fs, TEXT_OFF) != NULL && fn_at(&fs, TEXT_OFF)->len == 0x18);
	CK(fn_at(&fs, TEXT_OFF + 0x20) && fn_at(&fs, TEXT_OFF + 0x20)->len == 0xc);
#ifndef FNTAB_OLD_API_ONLY
	CK(fn_at(&fs, TEXT_OFF + 0x20) && fn_at(&fs, TEXT_OFF + 0x20)->source == KGENOME_FN_S_WALK && (fn_at(&fs, TEXT_OFF + 0x20)->flags & KGENOME_FN_F_GAP));
#endif
	kgenome_funcs_free(&fs);
}

/*
 * CN-5's SECOND fix (this round): MIPS o32 PIC's OTHER convention - a function that recomputes its OWN
 * $gp from $t9 at entry (`lui $gp,hi; addiu $gp,$gp,lo; addu $gp,$gp,$t9`) instead of reading the
 * walk-wide one the earlier fix reads from `.got` directly. S here is exactly such a function: its own
 * prologue computes $gp = (0<<16 + (-0x18)) + S's own entry VA, which lands exactly on this fixture's
 * `.got` address (want_gp = S_entry_va - 0x18, chosen so the arithmetic is worth checking - a negative,
 * sign-extended `lo` - while keeping every encoded 16-bit field small); `lw $t9, 0x6c($gp)` then reads
 * A's address out of the one GOT slot the object carries, and `jalr $t9` is resolved through it exactly
 * as t_walk_mips_indirect_jalr_got resolves its walk-wide case.
 *
 * NOT TESTED BY fs.n ALONE: an experiment run while writing this test (forcing mips_got_target to always
 * refuse, i.e. simulating "no CN-5 resolution at all") left t_walk_mips_indirect_jalr_got's fs.n == 3
 * assertion GREEN regardless - REACH's gap step (S ends at its own `jr ra`, the zero fill is recognised
 * padding, A's bytes independently decode and end) recovers A on its own, with no call edge needed. So
 * fs.n == 3 here is confirmatory, not proof of resolution; the proof is the direct read of the walk's own
 * call-target list below, which is empty of A's address unless pass_a actually resolved the `jalr $t9`.
 */
static void t_walk_mips_indirect_jalr_prologue_gp(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_func_set fs;
	struct kgenome_diag_walk *wk;
	uint8_t t[0x34];
	uint8_t got[4];
	uint64_t a_va, s_entry_va, got_va, want_gp;
	uint32_t n, ne, i;
	const uint64_t *ent;
	int seen_a = 0;

	memset(t, 0, sizeof t);
	w32(t + 0x00, 1, 0x3C1C0000u);     /* S: lui   $gp, 0 */
	w32(t + 0x04, 1, 0x279CFFE8u);     /* S: addiu $gp, $gp, -0x18 */
	w32(t + 0x08, 1, 0x0399E021u);     /* S: addu  $gp, $gp, $t9 */
	w32(t + 0x0c, 1, 0x8F99006Cu);     /* S: lw    $t9, 0x6c($gp) (A's GOT slot, once $gp is this function's own) */
	w32(t + 0x10, 1, 0x0320f809u);     /* S: jalr $t9 */
	w32(t + 0x14, 1, 0u);              /* delay slot */
	w32(t + 0x18, 1, 0x03e00008u);     /* S: jr ra */
	w32(t + 0x1c, 1, 0u);              /* delay slot, S ends here (0x20 bytes) */
	/* [0x20, 0x28): the linker's zero fill (MIPS zeronop) */
	w32(t + 0x28, 1, 0x24020001u);     /* A: addiu v0,0,1 */
	w32(t + 0x2c, 1, 0x03e00008u);     /* A: jr ra */
	w32(t + 0x30, 1, 0u);              /* A: delay slot, ends the text exactly */

	memset(&in, 0, sizeof in);
	in.be = 1; in.em = 8; in.base = 0x400000u; in.text = t; in.text_n = sizeof t; in.rodata_n = 0x20; in.sections = 1;
	s_entry_va = in.base + TEXT_OFF;
	a_va = in.base + TEXT_OFF + 0x28;
	/* The file's own layout (elf_build's `layout()`, reproduced here: ro_off = TEXT_OFF + text_n,
	 * got_off = ro_off + rodata_n, both already 4-aligned) - needed up front because the `lw`'s
	 * offset below must already be encoded relative to where $gp (want_gp, from the prologue's own
	 * arithmetic: hi(0)<<16 + lo(-0x18) + s_entry_va) will actually sit once the prologue runs. */
	got_va = in.base + TEXT_OFF + sizeof t + in.rodata_n;
	want_gp = s_entry_va - 0x18u;
	CK(got_va - want_gp == 0x6cu);     /* the fixture's own arithmetic, checked: this is the offset encoded into the `lw` above */
	memset(got, 0, sizeof got);
	{ struct wr gw = { got, 1 }; p32(&gw, 0, (uint32_t)a_va); }
	in.got = got; in.got_n = sizeof got;
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));

	/* THE PROOF: pass_a's own call-target list holds A's offset - resolved through the per-function
	 * $gp the prologue computed, not the (absent, no walk-wide `.got` relationship was set up for S's
	 * own entry) old single-$gp path. */
	wk = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_ensure(wk, &o, B, n, 0));
	ent = kgenome_diag_walk_entries(wk, &ne);
	for (i = 0; i < ne; i++)
		if (ent[i] == TEXT_OFF + 0x28)
			seen_a = 1;
	CK(seen_a);
	kgenome_diag_walk_free(wk);

	kgenome_diag_funcs_of(&o, B, n, &fs);
	CK(fs.n == 2);                                     /* S, A (REACH's gap step would find A too - see the comment above) */
	CK(fn_at(&fs, TEXT_OFF) != NULL);
	CK(fn_at(&fs, TEXT_OFF + 0x28) != NULL);
	kgenome_funcs_free(&fs);
}

/*
 * Conservative fallback, explicit: the SAME three registers and the SAME GOT value as the test above,
 * but the middle instruction of the prologue is not `addiu $gp,$gp,lo` - it is an unrelated instruction
 * (`addiu $t0,$t0,1`, chosen so it writes neither $gp nor $t9 and so changes nothing else pass_a tracks)
 * - so the 3-instruction sequence never completes: pgp_state resets at the second step and pgp_known is
 * never set. This object carries no `.got`-derived walk-wide $gp either (mips_gp_of finds no `.got`
 * relationship to S's own entry worth setting up here), so BOTH of CN-5's resolution paths have nothing
 * to resolve through and `jalr $t9` is left exactly as before - no crash, no guess, the GOT slot read by
 * `lw` is simply never reached by the matcher.
 */
static void t_walk_mips_indirect_jalr_prologue_gp_broken(void)
{
	struct elf_in in;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_diag_walk *wk;
	uint8_t t[0x34];
	uint32_t n, ne, i;
	const uint64_t *ent;
	int seen_a = 0;

	memset(t, 0, sizeof t);
	w32(t + 0x00, 1, 0x3C1C0000u);     /* S: lui   $gp, 0 (same as above) */
	w32(t + 0x04, 1, 0x25080001u);     /* S: addiu $t0, $t0, 1 - NOT the expected addiu $gp,$gp,lo: breaks the sequence */
	w32(t + 0x08, 1, 0x0399E021u);     /* S: addu  $gp, $gp, $t9 - reached with pgp_state back at 0, so this does not complete anything either */
	w32(t + 0x0c, 1, 0x8F99006Cu);     /* S: lw    $t9, 0x6c($gp) */
	w32(t + 0x10, 1, 0x0320f809u);     /* S: jalr $t9 */
	w32(t + 0x14, 1, 0u);              /* delay slot */
	w32(t + 0x18, 1, 0x03e00008u);     /* S: jr ra */
	w32(t + 0x1c, 1, 0u);              /* delay slot, S ends here */
	/* [0x20, 0x28): the linker's zero fill (MIPS zeronop) */
	w32(t + 0x28, 1, 0x24020001u);     /* A: addiu v0,0,1 */
	w32(t + 0x2c, 1, 0x03e00008u);     /* A: jr ra */
	w32(t + 0x30, 1, 0u);              /* A: delay slot, ends the text exactly */

	memset(&in, 0, sizeof in);
	in.be = 1; in.em = 8; in.base = 0x400000u; in.text = t; in.text_n = sizeof t; in.rodata_n = 0x20; in.sections = 1;
	/* No `.got` member set: this object has no section a walk-wide $gp could be fixed from either,
	 * so the fallback is pinned with BOTH of CN-5's resolution paths unavailable to it. */
	n = elf_build(&in, B);
	CK(parse(B, n, &ei, &o));

	wk = kgenome_diag_walk_new();
	CK(kgenome_diag_walk_ensure(wk, &o, B, n, 0));
	ent = kgenome_diag_walk_entries(wk, &ne);
	for (i = 0; i < ne; i++)
		if (ent[i] == TEXT_OFF + 0x28)
			seen_a = 1;
	CK(!seen_a);                       /* no edge to A: the broken prologue resolves nothing, and crashes nothing */
	kgenome_diag_walk_free(wk);
}

#ifndef FNTAB_OLD_API_ONLY
/* ---- merge and ends, pure ------------------------------------------------------------------------------------------------------ */

static struct kgenome_func mk(uint64_t off, uint64_t len, uint8_t source, uint8_t end)
{
	struct kgenome_func f;

	memset(&f, 0, sizeof f);
	f.off = off; f.len = len; f.source = source; f.end_source = end;
	return f;
}

static int same_tables(const struct kgenome_func_set *a, const struct kgenome_func_set *b)
{
	return a->n == b->n && (!a->n || !memcmp(a->v, b->v, a->n * sizeof *a->v)) && a->n_disagree == b->n_disagree && a->n_extra == b->n_extra;
}

static void t_merge(void)
{
	struct kgenome_fntab_list l, l2;
	struct kgenome_func_set a, b;
	struct kgenome_func e[8];
	unsigned i, k;

	/* rank: SYMTAB over FDE over a bare start; a start inside an exact body is dropped; a label nested in a body of the same source is dropped (the old rule) */
	e[0] = mk(0x100, 0x40, KGENOME_FN_S_SYMTAB, KGENOME_FN_E_SYMBOL);
	e[1] = mk(0x100, 0x30, KGENOME_FN_S_FDE, KGENOME_FN_E_UNWIND);          /* same start, other end: disagreement */
	e[2] = mk(0x110, 0, KGENOME_FN_S_WALK, KGENOME_FN_E_NONE);              /* inside A's body */
	e[3] = mk(0x140, 0, KGENOME_FN_S_WALK, KGENOME_FN_E_NONE);              /* just after: kept, open */
	e[4] = mk(0x120, 0x10, KGENOME_FN_S_SYMTAB, KGENOME_FN_E_SYMBOL);       /* nested label, same source */
	e[5] = mk(0x200, 0x10, KGENOME_FN_S_FDE, KGENOME_FN_E_UNWIND);
	memset(&l, 0, sizeof l); memset(&a, 0, sizeof a);
	for (i = 0; i < 6; i++) CK(kgenome_fntab_list_add(&l, &e[i]));
	kgenome_fntab_merge(&l, 0, &a);
	CK(a.n == 3);
	CK(a.v[0].off == 0x100 && a.v[0].len == 0x40 && (a.v[0].flags & KGENOME_FN_F_DISAGREE) && a.v[0].source == (KGENOME_FN_S_SYMTAB | KGENOME_FN_S_FDE));
	CK(a.v[1].off == 0x140 && a.v[1].end_source == KGENOME_FN_E_NONE && a.v[1].len == 0);
	CK(a.v[2].off == 0x200 && a.v[2].len == 0x10);
	CK(a.n_disagree == 1);
	/* order independence and idempotence: every rotation of the input gives the same table */
	for (k = 1; k < 6; k++) {
		memset(&l2, 0, sizeof l2); memset(&b, 0, sizeof b);
		for (i = 0; i < 6; i++) CK(kgenome_fntab_list_add(&l2, &e[(i + k) % 6]));
		kgenome_fntab_merge(&l2, 0, &b);
		CK(same_tables(&a, &b));
		kgenome_funcs_free(&b);
	}
	/* a second merge of an already merged list (its entries fed back) changes nothing */
	memset(&l2, 0, sizeof l2); memset(&b, 0, sizeof b);
	for (i = 0; i < a.n; i++) CK(kgenome_fntab_list_add(&l2, &a.v[i]));
	kgenome_fntab_merge(&l2, 0, &b);
	CK(b.n == a.n && !memcmp(a.v, b.v, a.n * sizeof *a.v));
	kgenome_funcs_free(&a); kgenome_funcs_free(&b);

	/* a source in the check-only mask: matched starts add to the sources, a start the others do not name is counted and not kept; outside every body it says PARTIAL (P_SYMTAB) */
	e[0] = mk(0x100, 0x10, KGENOME_FN_S_SYMTAB, KGENOME_FN_E_SYMBOL);
	e[1] = mk(0x100, 0x10, KGENOME_FN_S_FDE, KGENOME_FN_E_UNWIND);
	e[2] = mk(0x108, 0x04, KGENOME_FN_S_FDE, KGENOME_FN_E_UNWIND);          /* inside the body: counted */
	e[3] = mk(0x300, 0x10, KGENOME_FN_S_FDE, KGENOME_FN_E_UNWIND);          /* outside: the symbols lack it */
	memset(&l, 0, sizeof l); memset(&a, 0, sizeof a);
	for (i = 0; i < 4; i++) CK(kgenome_fntab_list_add(&l, &e[i]));
	kgenome_fntab_merge(&l, KGENOME_FN_S_FDE, &a);
	/* (the FDE at 0x108 sits inside a body whose symbol an FDE already joined: a label of the same source, silent as it always was) */
	CK(a.n == 1 && a.v[0].source == (KGENOME_FN_S_SYMTAB | KGENOME_FN_S_FDE) && a.n_extra == 1 && (a.partial & KGENOME_FNTAB_P_SYMTAB));
	kgenome_funcs_free(&a);
	/* an unwind record inside a symbol's body that the symbol's own FDE did not join: counted, and it does not say PARTIAL (the symbols hold the function) */
	e[0] = mk(0x100, 0x10, KGENOME_FN_S_SYMTAB, KGENOME_FN_E_SYMBOL);
	e[1] = mk(0x108, 0x04, KGENOME_FN_S_FDE, KGENOME_FN_E_UNWIND);
	memset(&l, 0, sizeof l); memset(&a, 0, sizeof a);
	for (i = 0; i < 2; i++) CK(kgenome_fntab_list_add(&l, &e[i]));
	kgenome_fntab_merge(&l, KGENOME_FN_S_FDE, &a);
	CK(a.n == 1 && a.n_extra == 1 && !(a.partial & KGENOME_FNTAB_P_SYMTAB));
	kgenome_funcs_free(&a);
	/* an empty list and a NULL-able free */
	memset(&l, 0, sizeof l); memset(&a, 0, sizeof a);
	kgenome_fntab_merge(&l, 0, &a);
	CK(a.n == 0 && a.v == NULL);
	kgenome_fntab_list_free(&l);
	kgenome_fntab_list_free(NULL);
}

static void t_ends(void)
{
	struct kgenome_fntab_list l;
	struct kgenome_func_set s;
	struct kgenome_func f;
	/* padding runs [0x1b,0x20) and [0x2e,0x30) and [0x3c,0x40) (ascending) */
	static const uint64_t pad[6] = { 0x1b, 0x20, 0x2e, 0x30, 0x3c, 0x40 };
	const struct kgenome_fntab_extent ext = { 0x10, 0x30 };         /* [0x10, 0x40) */

	memset(&l, 0, sizeof l); memset(&s, 0, sizeof s);
	f = mk(0x10, 0, KGENOME_FN_S_WALK, KGENOME_FN_E_NONE); CK(kgenome_fntab_list_add(&l, &f));
	f = mk(0x20, 0, KGENOME_FN_S_WALK, KGENOME_FN_E_NONE); CK(kgenome_fntab_list_add(&l, &f));
	f = mk(0x30, 0, KGENOME_FN_S_WALK, KGENOME_FN_E_NONE); CK(kgenome_fntab_list_add(&l, &f));
	f = mk(0x50, 0, KGENOME_FN_S_WALK, KGENOME_FN_E_NONE); CK(kgenome_fntab_list_add(&l, &f));     /* beyond the extent */
	kgenome_fntab_merge(&l, 0, &s);
	kgenome_fntab_ends(&s, &ext, 1, pad, 3);
	CK(s.n == 3);
	CK(s.v[0].off == 0x10 && s.v[0].len == 0x0b && s.v[0].end_source == KGENOME_FN_E_TRIMMED);     /* 0x10..0x1b: the run [0x1b,0x20) ends at the next start */
	CK(s.v[1].off == 0x20 && s.v[1].len == 0x0e && s.v[1].end_source == KGENOME_FN_E_TRIMMED);     /* 0x20..0x2e */
	CK(s.v[2].off == 0x30 && s.v[2].len == 0x0c && s.v[2].end_source == KGENOME_FN_E_TRIMMED);     /* to the end of the extent, less [0x3c,0x40) */
	CK(s.n_extra == 1);                                                                          /* 0x50: in no extent */
	CK((s.partial & KGENOME_FNTAB_P_ENDS) && (s.v[0].flags & KGENOME_FN_F_END_OPEN));
	kgenome_funcs_free(&s);
	/* a run that covers a whole function is not cut (the function is only padding: it stays one byte-for-byte unit) */
	{
		static const uint64_t all[2] = { 0x10, 0x20 };

		memset(&l, 0, sizeof l); memset(&s, 0, sizeof s);
		f = mk(0x10, 0, KGENOME_FN_S_WALK, KGENOME_FN_E_NONE); CK(kgenome_fntab_list_add(&l, &f));
		f = mk(0x20, 0, KGENOME_FN_S_WALK, KGENOME_FN_E_NONE); CK(kgenome_fntab_list_add(&l, &f));
		kgenome_fntab_merge(&l, 0, &s);
		kgenome_fntab_ends(&s, &ext, 1, all, 1);
		CK(s.n == 2 && s.v[0].len == 0x10 && s.v[0].end_source == KGENOME_FN_E_NEXT_START);
		kgenome_funcs_free(&s);
	}
	/* an exact entry is never touched, padding or not */
	memset(&l, 0, sizeof l); memset(&s, 0, sizeof s);
	f = mk(0x10, 0x10, KGENOME_FN_S_SYMTAB, KGENOME_FN_E_SYMBOL); CK(kgenome_fntab_list_add(&l, &f));
	kgenome_fntab_merge(&l, 0, &s);
	kgenome_fntab_ends(&s, &ext, 1, pad, 3);
	CK(s.n == 1 && s.v[0].len == 0x10 && s.v[0].end_source == KGENOME_FN_E_SYMBOL && !(s.partial & KGENOME_FNTAB_P_ENDS));
	kgenome_funcs_free(&s);
}

/* The cap is reported, never silent: KGENOME_FNTAB_MAX entries in, one more is refused and the list says so. */
static void t_cap(void)
{
	struct kgenome_fntab_list l;
	struct kgenome_func_set s;
	struct kgenome_func f;
	uint32_t i;

	memset(&l, 0, sizeof l); memset(&s, 0, sizeof s);
	for (i = 0; i < KGENOME_FNTAB_MAX; i++) {
		f = mk(0x1000u + 16u * (uint64_t)i, 8, KGENOME_FN_S_SYMTAB, KGENOME_FN_E_SYMBOL);
		if (!kgenome_fntab_list_add(&l, &f))
			break;
	}
	CK(i == KGENOME_FNTAB_MAX && l.n == KGENOME_FNTAB_MAX && !(l.partial & KGENOME_FNTAB_P_CAP));
	f = mk(0x1000u + 16u * (uint64_t)i, 8, KGENOME_FN_S_SYMTAB, KGENOME_FN_E_SYMBOL);
	CK(!kgenome_fntab_list_add(&l, &f) && (l.partial & KGENOME_FNTAB_P_CAP) && l.n == KGENOME_FNTAB_MAX);
	kgenome_fntab_merge(&l, 0, &s);
	CK(s.n == KGENOME_FNTAB_MAX && (s.partial & KGENOME_FNTAB_P_CAP));
	kgenome_funcs_free(&s);
}
#endif

int main(void)
{
	static const struct arch_fx fx[] = {
		/* ARM LE: S = bl, bl, bx lr (12) + 5 nops; A = mov, bx lr (8) + 2 nops; B = 3 insns (12) + 1 nop */
		{ "arm-le", 0, 0, 40, 0x10000u, 0, 8, 12, 12, 0xe1a00000u },
		/* ARM, the linker's zero fill between functions */
		{ "arm-le-zero", 0, 0, 40, 0x10000u, 0, 8, 12, 12, 0u },
		/* MIPS BE: A = addiu, jr ra, delay slot (12, the slot is part of it) + 1 nop; B = 4 words, the slot last; S = jal,nop,jal,nop,jr,slot (24) + 2 nops */
		{ "mips-be", 0, 1, 8, 0x400000u, 0, 12, 16, 24, 0 },
		/* PowerPC BE: S = bl, bl, blr (12) + 5 nops; A = li, blr (8) + 2; B = 12 + 1 */
		{ "ppc-be", 0, 1, 20, 0x10000000u, 0, 8, 12, 12, 0 },
	};
	unsigned i;

#ifndef FNTAB_OLD_API_ONLY
	t_selector();
	t_merge();
	t_ends();
	t_cap();
	t_fde_hostile();
#endif
	t_symtab_kinds();
	t_symtab_thumb();
	t_fde_sections();
	t_fde_no_sections();
	t_symtab_fde_disagree();
	t_walk_x86();
	t_walk_no_calls_collapse();
	t_walk_padding_crossing();
	for (i = 0; i < sizeof fx / sizeof *fx; i++)
		t_walk_arch(&fx[i]);
	t_walk_mips_indirect_jalr();
	t_walk_mips_indirect_jalr_got();
	t_walk_mips_indirect_jalr_no_lw();
	t_walk_mips_indirect_jalr_prologue_gp();
	t_walk_mips_indirect_jalr_prologue_gp_broken();
	printf("fntab: %d failure(s)\n", fails);
	return fails != 0;
}
