/*
 * elf_exec_seg - ELF-SEC-EXEC-CODE: kgenome_fntab_symtab (funcs.c) used to admit a
 * FUNC symbol as a function on the SECTION flag SHF_EXECINSTR alone, never
 * cross-checked against diag_code.c's own AUTHORITATIVE segment-level definition of
 * ELF code (kgenome_elf_seg_is_code: PT_LOAD && PF_X). A crafted ELF with a FUNC
 * symbol in an SHF_EXECINSTR section whose real VA falls outside every executable
 * PT_LOAD segment got its bytes decoded, CFG-signed and mutation-hashed as a
 * function regardless - the same class of admission as PE-RSRC-EXEC-CODE.
 *
 * fntab_kit.h's elf_build() always emits exactly ONE PT_LOAD, R+X, over the whole
 * file - useless for this defect, which is a MISMATCH between a section's flag and
 * its own segment's permission. This file keeps its own small builder instead,
 * linked against libkgenome.a alone like every file of this directory (fntab_kit.h's
 * own header comment already notes fntab.c keeps a separate copy of the same
 * writer for the identical reason - a test needing a layout the shared kit does not
 * support does not bend the kit for it).
 *
 * Two ADJACENT PT_LOAD segments, with the file's own layout as the VA (no slide),
 * so a VA is trivial to reason about: segment 0 [EBASE, EBASE+SEG0_LEN) R+X holds
 * the real .text; segment 1 [EBASE+SEG0_LEN, EBASE+SEG0_LEN+SEG1_LEN) R+W (NO X)
 * holds .fake_text - a section the table ALSO marks SHF_EXECINSTR, the lie this
 * defect is about. Adjacent and non-overlapping on purpose: kgenome_elf_load_at_va
 * (under kgenome_elf_va_to_off) returns the FIRST segment covering a VA, so an
 * overlapping segment 1 would resolve through segment 0 regardless of its own
 * permission and prove nothing about the fix.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/fntab.h>
#include <genotype/image/elf_image.h>

static int fails;
static unsigned long checks;
#define CK(c) do { checks++; if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void p16(uint8_t *b, uint32_t at, uint32_t v) { b[at] = (uint8_t)v; b[at + 1u] = (uint8_t)(v >> 8); }
static void p32(uint8_t *b, uint32_t at, uint32_t v) { unsigned i; for (i = 0; i < 4; i++) b[at + i] = (uint8_t)(v >> (8u * i)); }
static void p64(uint8_t *b, uint32_t at, uint64_t v) { unsigned i; for (i = 0; i < 8; i++) b[at + i] = (uint8_t)(v >> (8u * i)); }

static int parse(const uint8_t *b, uint32_t n, struct kgenome_elf_info *ei, struct kgenome_obj *o)
{
	memset(ei, 0, sizeof *ei);
	memset(o, 0, sizeof *o);
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), ei, o))
		return 0;
	o->file_header = ei;
	return 1;
}

#define EBASE     0x400000ull
#define TEXT_OFF  0x100u
#define TEXT_LEN  0x10u
#define SEG0_LEN  (TEXT_OFF + TEXT_LEN)         /* 0x110: segment 0 covers [0, SEG0_LEN) */
#define FAKE_OFF  SEG0_LEN                      /* segment 1 starts exactly where segment 0 ends */
#define FAKE_LEN  0x10u
#define SEG1_LEN  FAKE_LEN
#define FAR_VA    (EBASE + 0x100000ull)         /* covered by NEITHER segment */

struct eseg_sym { const char *name; uint64_t value; uint64_t size; uint16_t shndx; };

/*
 * Builds the file into `out` (at least 0x2000 bytes); returns its size. 64-bit LE
 * x86-64 ET_EXEC - the shape kgenome_fntab_symtab's new segment cross-check actually
 * runs on (an ET_REL object - a .o, a .ko - has no program headers at all and the
 * strategy itself skips the cross-check there; see funcs.c).
 */
static uint32_t build_exec_seg_elf(uint8_t *out, const struct eseg_sym *syms, uint32_t nsym)
{
	char strtab[256];
	static const char shstrtab[] = "\0.text\0.fake_text\0.symtab\0.strtab\0.shstrtab";
	const uint32_t shstr_n = (uint32_t)sizeof shstrtab;
	uint32_t strtab_n = 1u, symtab_off, strtab_off, shstr_off, sh_off, i;

	memset(out, 0, 0x2000u);

	/* ELF header */
	out[0] = 0x7f; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
	out[4] = 2; out[5] = 1; out[6] = 1;              /* ELFCLASS64, ELFDATA2LSB, EV_CURRENT */
	p16(out, 16, 2);                                 /* e_type: ET_EXEC */
	p16(out, 18, 62);                                /* e_machine: EM_X86_64 */
	p32(out, 20, 1);                                 /* e_version */
	p64(out, 24, EBASE + TEXT_OFF);                  /* e_entry */
	p64(out, 32, 64);                                /* e_phoff: right after the header */
	p16(out, 52, 64);                                /* e_ehsize */
	p16(out, 54, 56);                                /* e_phentsize */
	p16(out, 56, 2);                                 /* e_phnum: two segments */

	/* program header 0: PT_LOAD, PF_R|PF_X, [0, SEG0_LEN) */
	{
		const uint32_t ph = 64u;

		p32(out, ph, 1); p32(out, ph + 4, 5);
		p64(out, ph + 8, 0); p64(out, ph + 16, EBASE); p64(out, ph + 24, EBASE);
		p64(out, ph + 32, SEG0_LEN); p64(out, ph + 40, SEG0_LEN); p64(out, ph + 48, 0x1000);
	}
	/* program header 1: PT_LOAD, PF_R|PF_W (no X), [FAKE_OFF, FAKE_OFF+SEG1_LEN), adjacent VA */
	{
		const uint32_t ph = 64u + 56u;

		p32(out, ph, 1); p32(out, ph + 4, 6);
		p64(out, ph + 8, FAKE_OFF); p64(out, ph + 16, EBASE + FAKE_OFF); p64(out, ph + 24, EBASE + FAKE_OFF);
		p64(out, ph + 32, SEG1_LEN); p64(out, ph + 40, SEG1_LEN); p64(out, ph + 48, 0x1000);
	}

	/* .text / .fake_text bytes: arbitrary - kgenome_fntab_symtab decodes nothing */
	memset(out + TEXT_OFF, 0x90, TEXT_LEN);
	memset(out + FAKE_OFF, 0x90, FAKE_LEN);

	symtab_off = (FAKE_OFF + FAKE_LEN + 7u) & ~7u;
	strtab_off = symtab_off + (nsym + 1u) * 24u;        /* +1: the null symbol */
	strtab[0] = 0;
	{
		uint32_t at = 1;

		for (i = 0; i < nsym; i++) {
			size_t ln = strlen(syms[i].name) + 1u;

			memcpy(strtab + at, syms[i].name, ln);
			at += (uint32_t)ln;
			strtab_n += (uint32_t)ln;
		}
	}
	memcpy(out + strtab_off, strtab, strtab_n);
	for (i = 0; i < nsym; i++) {
		const uint32_t o = symtab_off + (i + 1u) * 24u;
		uint32_t nameoff = 1u, k;

		for (k = 0; k < i; k++)
			nameoff += (uint32_t)strlen(syms[k].name) + 1u;
		p32(out, o, nameoff);
		out[o + 4] = 0x12;                          /* STB_GLOBAL<<4 | STT_FUNC */
		p16(out, o + 6, syms[i].shndx);
		p64(out, o + 8, syms[i].value);
		p64(out, o + 16, syms[i].size);
	}

	shstr_off = strtab_off + strtab_n;
	memcpy(out + shstr_off, shstrtab, shstr_n);

	sh_off = (shstr_off + shstr_n + 7u) & ~7u;
	/* sections: null, .text, .fake_text, .symtab, .strtab, .shstrtab */
	{
		const struct { uint32_t name, type; uint64_t flags, addr; uint32_t off, size, link, entsize; } s[6] = {
			{ 0,  0, 0, 0,              0,          0,                     0, 0 },
			{ 1,  1, 6, EBASE + TEXT_OFF, TEXT_OFF, TEXT_LEN,              0, 0 },   /* .text: ALLOC|EXECINSTR */
			{ 7,  1, 6, EBASE + FAKE_OFF, FAKE_OFF, FAKE_LEN,              0, 0 },   /* .fake_text: ALLOC|EXECINSTR - the lie */
			{ 18, 2, 0, 0,              symtab_off, (nsym + 1u) * 24u,     4, 24 },  /* .symtab -> sh_link .strtab (index 4) */
			{ 26, 3, 0, 0,              strtab_off, strtab_n,              0, 0 },
			{ 34, 3, 0, 0,              shstr_off,  shstr_n,               0, 0 },
		};

		for (i = 0; i < 6; i++) {
			const uint32_t o = sh_off + i * 64u;

			p32(out, o, s[i].name); p32(out, o + 4, s[i].type);
			p64(out, o + 8, s[i].flags); p64(out, o + 16, s[i].addr);
			p64(out, o + 24, s[i].off); p64(out, o + 32, s[i].size);
			p32(out, o + 40, s[i].link); p64(out, o + 56, s[i].entsize);
		}
	}
	p64(out, 40, sh_off);        /* e_shoff */
	p16(out, 58, 64);            /* e_shentsize */
	p16(out, 60, 6);             /* e_shnum */
	p16(out, 62, 5);             /* e_shstrndx: .shstrtab is the last section */

	return sh_off + 6u * 64u;
}

static uint8_t EB[0x2000];

/*
 * The core of the defect: a FUNC symbol in an SHF_EXECINSTR section (shndx 2,
 * .fake_text) whose VA sits in segment 1, R+W and NOT executable. On the unfixed
 * strategy this is kept exactly like a real function (same shape as "good_fn" in
 * segment 0); fixed, it must be excluded while "good_fn" still is not - a flag that
 * is wrong by itself proves nothing without a control that stays right.
 */
static void t_section_lies_segment_does_not(void)
{
	const struct eseg_sym syms[2] = {
		{ "good_fn", EBASE + TEXT_OFF, 8, 1 },
		{ "evil_fn", EBASE + FAKE_OFF, 8, 2 },
	};
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	uint32_t n;

	n = build_exec_seg_elf(EB, syms, 2);
	CK(parse(EB, n, &ei, &o));
	CK(kgenome_elf_seg_is_code(&ei.seg[0]));
	CK(!kgenome_elf_seg_is_code(&ei.seg[1]));

	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(EB, n), &ei, 0, &l);
	CK(l.status == KGENOME_OK);
	CK(l.n == 1);
	if (l.n == 1) {
		CK(l.v[0].off == TEXT_OFF);
		CK(l.v[0].len == 8);
	}
	kgenome_fntab_list_free(&l);
}

/*
 * Boundary: the LAST byte of the executable segment (still code) against the FIRST
 * byte past it (the first byte of the non-executable one, "evil_fn"'s own address
 * above - so this is the same edge from the other side, naming it explicitly as the
 * project's test discipline asks for straddling cases).
 */
static void t_segment_edge(void)
{
	const struct eseg_sym syms[2] = {
		{ "edge_in_fn",  EBASE + SEG0_LEN - 1u, 1, 1 },   /* last byte of segment 0 / .text */
		{ "edge_out_fn", EBASE + SEG0_LEN,      1, 2 },   /* first byte of segment 1 / .fake_text */
	};
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	uint32_t n;

	n = build_exec_seg_elf(EB, syms, 2);
	CK(parse(EB, n, &ei, &o));

	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(EB, n), &ei, 0, &l);
	CK(l.n == 1);
	if (l.n == 1)
		CK(l.v[0].off == SEG0_LEN - 1u && l.v[0].len == 1);
	kgenome_fntab_list_free(&l);
}

/*
 * Defence in depth, named explicitly: a symbol whose VA is covered by NO segment at
 * all (not even a non-executable one) is already excluded before this fix, by
 * kgenome_elf_va_to_off itself (res 0: no PT_LOAD claims the address). The fix adds
 * the case where a PT_LOAD DOES claim it but without PF_X; this case must keep
 * working exactly as before - a regression here would mean the new check broke the
 * older one rather than adding to it.
 */
static void t_no_segment_at_all(void)
{
	const struct eseg_sym syms[1] = {
		{ "orphan_fn", FAR_VA, 8, 2 },     /* shndx 2: SHF_EXECINSTR is set, VA is not covered by anything */
	};
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_fntab_list l;
	uint32_t n;

	n = build_exec_seg_elf(EB, syms, 1);
	CK(parse(EB, n, &ei, &o));

	memset(&l, 0, sizeof l);
	kgenome_fntab_symtab(kof_buf_make(EB, n), &ei, 0, &l);
	CK(l.n == 0);
	kgenome_fntab_list_free(&l);
}

int main(void)
{
	t_section_lies_segment_does_not();
	t_segment_edge();
	t_no_segment_at_all();
	printf("elf_exec_seg: %d failure(s) of %lu check(s)\n", fails, checks);
	return fails != 0;
}
