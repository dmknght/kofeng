/*
 * lineage_raw.h - a raw ELF for the lineage tests: an ELF header, one PT_LOAD of the whole file, the code after them (what a hand-made
 * stager is), written byte by byte from hex. Header only, every function static: lineage_sites.c and lineage_frame.c build their system-call
 * programs with it.
 */
#ifndef KGENOME_TESTS_LINEAGE_RAW_H
#define KGENOME_TESTS_LINEAGE_RAW_H

#include <stdio.h>
#include <string.h>
#include "lineage_img.h"

/* ---- a raw ELF: header, one PT_LOAD of the whole file, the code after them (what a hand-made stager is) ---- */

struct rawelf {
	uint8_t b[4096];
	uint32_t n, code;
	int wide;
	/* 0 (the default): re_finish declares the code as one function (a .symtab FUNC with its size over a .text section, behind the segment), so the function table has a function
	 * to solve (2026-11-16: it is made from loader/ABI metadata only; an image that declares none is one unpartitioned unit the static lineage does not
	 * solve). 1: the image declares nothing, as a real stager does. */
	int no_meta;
};

static LA_UNUSED void re_init(struct rawelf *e, int wide)
{
	const int no_meta = e->no_meta;         /* the caller's choice survives the reset */

	memset(e, 0, sizeof *e);
	e->no_meta = no_meta;
	e->wide = wide;
	e->code = wide ? 64u + 56u : 52u + 32u;
	e->n = e->code;
}

static LA_UNUSED void re_b(struct rawelf *e, const char *hex)
{
	unsigned v;

	while (*hex) {
		if (*hex == ' ') {
			hex++;
			continue;
		}
		if (sscanf(hex, "%2x", &v) != 1)
			return;
		e->b[e->n++] = (uint8_t)v;
		hex += 2;
	}
}

static LA_UNUSED uint32_t re_here(const struct rawelf *e)
{
	return e->n;
}

/* a rel8 jump's displacement byte at `at` (the byte after the opcode) made to land on `to` */
static LA_UNUSED void re_fix8(struct rawelf *e, uint32_t at, uint32_t to)
{
	e->b[at] = (uint8_t)(int8_t)((int32_t)to - (int32_t)(at + 1u));
}

static LA_UNUSED void re_finish(struct rawelf *e)
{
	uint8_t *b = e->b;
	const uint64_t va = e->wide ? 0x400000u : 0x08048000u;

	b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
	b[4] = e->wide ? 2 : 1;
	b[5] = 1;
	b[6] = 1;
	if (e->wide) {
		lg_p16(b, 16, 2);
		lg_p16(b, 18, 62);
		lg_p32(b, 20, 1);
		lg_p64(b, 24, va + e->code);
		lg_p64(b, 32, 64);
		lg_p16(b, 52, 64);
		lg_p16(b, 54, 56);
		lg_p16(b, 56, 1);
		lg_p32(b, 64, 1);                       /* PT_LOAD */
		lg_p32(b, 68, 7);
		lg_p64(b, 72, 0);
		lg_p64(b, 80, va);
		lg_p64(b, 88, va);
		lg_p64(b, 96, e->n);
		lg_p64(b, 104, e->n + 0x1000u);
		lg_p64(b, 112, 0x1000);
	} else {
		lg_p16(b, 16, 2);
		lg_p16(b, 18, 3);
		lg_p32(b, 20, 1);
		lg_p32(b, 24, (uint32_t)(va + e->code));
		lg_p32(b, 28, 52);
		lg_p16(b, 40, 52);
		lg_p16(b, 42, 32);
		lg_p16(b, 44, 1);
		lg_p32(b, 52, 1);
		lg_p32(b, 56, 0);
		lg_p32(b, 60, (uint32_t)va);
		lg_p32(b, 64, (uint32_t)va);
		lg_p32(b, 68, e->n);
		lg_p32(b, 72, e->n + 0x1000u);
		lg_p32(b, 76, 7);
		lg_p32(b, 80, 0x1000);
	}
	if (!e->no_meta) {
		/* behind the segment (round 4: a start-only table declares a start, not a body, so the image declares its one function with an EXTENT): a .text
		 * section over the code and a .symtab FUNC sized to it. [symtab: null + f] [.strtab "\0f\0"] [.shstrtab] [5 headers: null .text .symtab .strtab .shstrtab] */
		static const char shs[] = "\0.text\0.symtab\0.strtab\0.shstrtab";
		const int w = e->wide;
		const uint32_t symsz = w ? 24u : 16u, shsz = w ? 64u : 40u, code_n = e->n - e->code;
		const uint32_t sym = (e->n + 7u) & ~7u, str = sym + 2u * symsz, shstr = str + 4u, sh = (shstr + (uint32_t)sizeof shs + 7u) & ~7u;

		memset(b + sym, 0, 2u * symsz + 4u);
		b[str + 1] = 'f';
		lg_p32(b, sym + symsz, 1);
		if (w) {
			b[sym + symsz + 4] = 0x12; lg_p16(b, sym + symsz + 6, 1); lg_p64(b, sym + symsz + 8, va + e->code); lg_p64(b, sym + symsz + 16, code_n);
		} else {
			lg_p32(b, sym + symsz + 4, (uint32_t)(va + e->code)); lg_p32(b, sym + symsz + 8, code_n); b[sym + symsz + 12] = 0x12; lg_p16(b, sym + symsz + 14, 1);
		}
		memcpy(b + shstr, shs, sizeof shs);
		memset(b + sh, 0, 5u * shsz);
#define RSEC(i, nm, ty, fl, addr, off, size, link, ent) do { const uint32_t o_ = sh + (i) * shsz; lg_p32(b, o_, nm); lg_p32(b, o_ + 4, ty); \
	if (w) { lg_p64(b, o_ + 8, fl); lg_p64(b, o_ + 16, addr); lg_p64(b, o_ + 24, off); lg_p64(b, o_ + 32, size); lg_p32(b, o_ + 40, link); lg_p64(b, o_ + 56, ent); } \
	else { lg_p32(b, o_ + 8, (uint32_t)(fl)); lg_p32(b, o_ + 12, (uint32_t)(addr)); lg_p32(b, o_ + 16, off); lg_p32(b, o_ + 20, size); lg_p32(b, o_ + 24, link); lg_p32(b, o_ + 36, ent); } } while (0)
		RSEC(1, 1, 1, 6, va + e->code, e->code, code_n, 0, 0);
		RSEC(2, 7, 2, 0, 0, sym, 2u * symsz, 3, symsz);
		RSEC(3, 15, 3, 0, 0, str, 4, 0, 0);
		RSEC(4, 23, 3, 0, 0, shstr, (uint32_t)sizeof shs, 0, 0);
#undef RSEC
		if (w) {
			lg_p64(b, 40, sh); lg_p16(b, 58, 64); lg_p16(b, 60, 5); lg_p16(b, 62, 4);
		} else {
			lg_p32(b, 32, sh); lg_p16(b, 46, 40); lg_p16(b, 48, 5); lg_p16(b, 50, 4);
		}
		e->n = sh + 5u * shsz;          /* the file holds them; the segment above ends where the code does */
	}
}

#endif /* KGENOME_TESTS_LINEAGE_RAW_H */
